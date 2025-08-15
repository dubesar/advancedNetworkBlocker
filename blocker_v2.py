#!/usr/bin/env python3
"""
macOS SiteBlocker — resilient website blocker (CLI + launchd daemon)

Design goals
------------
- Version-agnostic for modern macOS (Catalina+).
- CLI to start/extend/stop a timed block; spawns a root launchd daemon that self-heals.
- Multi-layer blocking to make it *hard* (not impossible) to bypass:
  1) /etc/hosts injection with immutable flag (chflags uchg) + periodic reassertion
  2) pf firewall anchor with a table of resolved IPs for blocked domains
  3) launchd daemon (root) with KeepAlive; optional user LaunchAgent monitor (disabled by default)
- Recovery-safe: fully revertible via `siteblocker stop --token <secret>`.
- A small “puzzle”/friction: a one-time secret split across 3 places (files/xattrs/plist arg). You must collect all parts to reconstruct the stop token if you forgot it.

**IMPORTANT**: Run the CLI with `sudo` for install and any action that modifies system files.

Tested paths only use the standard library and common macOS utilities: pfctl, scutil, dscacheutil, xattr, chflags, launchctl.

Usage (quick):

# install (generates the split stop token; no launchd involved)
sudo python3 siteblocker.py install

# test block
sudo python3 siteblocker.py block --minutes 2 --sites youtube.com
python3 siteblocker.py status

# after 2 minutes, clear manually
sudo python3 siteblocker.py repair

"""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import getpass
import hashlib
import json
import os
import platform
import random
import re
import secrets
import shlex
import socket
import string
import subprocess
import sys
import tempfile
import time
from typing import List, Set, Dict

# ---------- Constants & Paths ----------
# Manual-only mode (no background daemon). Set to True to disable all launchd behavior.
MANUAL_MODE = True
LAUNCHD_LABEL = "com.siteblocker.daemon"
DAEMON_ARG = "--daemon"
BASE_DIR = "/etc/siteblocker"
LOG_DIR = "/var/log"
STATE_PATH = f"{BASE_DIR}/state.json"
CONFIG_PATH = f"{BASE_DIR}/config.json"
SECRET_META_PATH = f"{BASE_DIR}/secret_meta.json"  # stores salted hash of stop token
PLIST_PATH = f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
HOSTS_PATH = "/etc/hosts"
HOSTS_MARK_START = "## SITEBLOCKER START"
HOSTS_MARK_END   = "## SITEBLOCKER END"
PF_ANCHOR_NAME = LAUNCHD_LABEL
PF_ANCHOR_FILE = f"/etc/pf.anchors/{PF_ANCHOR_NAME}"
PF_TABLE_FILE  = "/etc/pf.siteblocker.table"
PF_DEFAULT_IF  = None  # Autodetect active interface
XATTR_TOOL = "/usr/bin/xattr"

# Optional user LaunchAgent (disabled by default). If enabled, it checks that the daemon is loaded.
USER_AGENT_PLIST = os.path.expanduser("~/Library/LaunchAgents/com.siteblocker.guard.plist")

# ---------- Helpers ----------

def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def run(cmd: List[str], check=True, capture=False, text=True, input_data: str|None=None):
    """Run a subprocess with sane defaults."""
    # print debug
    # print("RUN:", shlex.join(cmd))
    res = subprocess.run(cmd, check=check, capture_output=capture, text=text, input=input_data)
    return res.stdout if capture else None


def atomic_write(path: str, data: str, mode=0o600):
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, dir=d) as tf:
        tf.write(data)
        tmp = tf.name
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def now_ts() -> int:
    return int(time.time())


def pretty_duration(seconds: int) -> str:
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    parts = []
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    if s and not h: parts.append(f"{s}s")
    return " ".join(parts) or "0s"


def require_root():
    if not is_root():
        print("[!] This action requires sudo/root.")
        sys.exit(1)


def macos_guard():
    if platform.system() != "Darwin":
        print("[!] This script is intended for macOS.")
        sys.exit(1)


def log(msg: str):
    ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")

# ---------- State & Config ----------

def load_json(path: str, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path: str, obj, mode=0o600):
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=True), mode=mode)

# ---------- Token / Puzzle Handling ----------

class TokenManager:
    """Manages the stop token. Stores salted sha256 and splits the clear token into 3 parts.
    Manual mode split locations:
      A) /usr/local/.siteblocker_partA (root-only file)
      B) xattr com.siteblocker.partB on PF_ANCHOR_FILE
      C) xattr com.siteblocker.partC on /etc/hosts
    All three base64 parts must be concatenated to reconstruct the full token.
    """
    PART_A_PATH = "/usr/local/.siteblocker_partA"
    XATTR_KEY = "com.siteblocker.partB"
    XATTR_KEY_C = "com.siteblocker.partC"

    @staticmethod
    def ensure_dirs():
        os.makedirs(BASE_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(TokenManager.PART_A_PATH), exist_ok=True)

    @staticmethod
    def generate_and_store_new() -> str:
        TokenManager.ensure_dirs()
        clear = base64.urlsafe_b64encode(secrets.token_bytes(24)).decode("ascii").rstrip("=")
        salt = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii")
        digest = sha256_hex(clear + ":" + salt)
        meta = {"salt": salt, "sha256": digest}
        save_json(SECRET_META_PATH, meta)

        # split into 3 chunks
        thirds = max(3, len(clear)//3)
        partA = clear[:thirds]
        partB = clear[thirds:2*thirds]
        partC = clear[2*thirds:]
        if not partC:
            partC = secrets.token_urlsafe(3)
            clear = partA + partB + partC
            meta["sha256"] = sha256_hex(clear + ":" + salt)
            save_json(SECRET_META_PATH, meta)

        # Store A (file)
        atomic_write(TokenManager.PART_A_PATH, base64.b64encode(partA.encode()).decode(), mode=0o600)

        # Ensure anchor file exists to host xattr
        if not os.path.exists(PF_ANCHOR_FILE):
            atomic_write(PF_ANCHOR_FILE, "# siteblocker anchor", mode=0o644)
        # Store B (xattr on anchor)
        try:
            run([XATTR_TOOL, "-w", TokenManager.XATTR_KEY, base64.b64encode(partB.encode()).decode(), PF_ANCHOR_FILE], check=True)
        except Exception:
            atomic_write(f"{BASE_DIR}/partB.b64", base64.b64encode(partB.encode()).decode(), mode=0o600)

        # Store C (xattr on /etc/hosts)
        try:
            run([XATTR_TOOL, "-w", TokenManager.XATTR_KEY_C, base64.b64encode(partC.encode()).decode(), HOSTS_PATH], check=False)
        except Exception:
            atomic_write(f"{BASE_DIR}/partC.b64", base64.b64encode(partC.encode()).decode(), mode=0o600)

        return clear, partC

    @staticmethod
    def set_plist_partC(plist_b64: str):
        # Not used in manual mode
        pass

    @staticmethod
    def verify(token: str) -> bool:
        meta = load_json(SECRET_META_PATH, {})
        if not meta:
            return False
        salt = meta.get("salt", "")
        dig = meta.get("sha256", "")
        return sha256_hex(token + ":" + salt) == dig

# ---------- Hosts Blocking ----------


def _chflags(path: str, flag: str):
    try:
        run(["/usr/bin/chflags", flag, path], check=False)
    except Exception:
        pass


def hosts_apply(block_domains: List[str]):
    """Insert our block section into /etc/hosts and set uchg flag."""
    # create block lines
    lines = []
    for d in sorted(set(block_domains)):
        d = d.strip()
        if not d or d.startswith("#"): continue
        lines.append(f"127.0.0.1\t{d}")
        lines.append(f"::1\t{d}")
        # common subdomains
        if not d.startswith("www."):
            lines.append(f"127.0.0.1\twww.{d}")
            lines.append(f"::1\twww.{d}")

    block = "\n".join([HOSTS_MARK_START] + lines + [HOSTS_MARK_END, ""]) + "\n"

    # remove immutable, edit, re-apply
    _chflags(HOSTS_PATH, "nouchg")
    with open(HOSTS_PATH, "r") as f:
        content = f.read()

    # strip previous block
    content = re.sub(rf"{re.escape(HOSTS_MARK_START)}[\s\S]*?{re.escape(HOSTS_MARK_END)}\n?", "", content, flags=re.M)
    new_content = content.rstrip() + "\n\n" + block
    atomic_write(HOSTS_PATH, new_content, mode=0o644)

    # flush DNS caches
    try:
        run(["/usr/bin/dscacheutil", "-flushcache"], check=False)
        run(["/usr/sbin/killall", "-HUP", "mDNSResponder"], check=False)
    except Exception:
        pass

    _chflags(HOSTS_PATH, "uchg")


def hosts_clear():
    _chflags(HOSTS_PATH, "nouchg")
    try:
        with open(HOSTS_PATH, "r") as f:
            content = f.read()
        content = re.sub(rf"{re.escape(HOSTS_MARK_START)}[\s\S]*?{re.escape(HOSTS_MARK_END)}\n?", "", content, flags=re.M)
        atomic_write(HOSTS_PATH, content, mode=0o644)
    except FileNotFoundError:
        pass
    finally:
        try:
            run(["/usr/bin/dscacheutil", "-flushcache"], check=False)
            run(["/usr/sbin/killall", "-HUP", "mDNSResponder"], check=False)
        except Exception:
            pass
        _chflags(HOSTS_PATH, "uchg")

# ---------- pf (packet filter) ----------

def pf_enable():
    run(["/sbin/pfctl", "-E"], check=False)


def pf_anchor_write_and_load(ips: Set[str]):
    # write table file
    atomic_write(PF_TABLE_FILE, "\n".join(sorted(ips)) + "\n", mode=0o644)

    # anchor rules reference the table file
    anchor_rules = f"""
# siteblocker pf anchor
# Autogenerated — DO NOT EDIT

# Load/maintain our table of blocked IPs
# (the file is updated separately by the daemon)
table <siteblocker_ips> persist file \"{PF_TABLE_FILE}\"

# Drop both directions quickly
block drop quick to <siteblocker_ips>
block drop quick from <siteblocker_ips>
"""
    atomic_write(PF_ANCHOR_FILE, anchor_rules, mode=0o644)

    # load the anchor into the live ruleset under name -a <anchor>
    run(["/sbin/pfctl", "-a", PF_ANCHOR_NAME, "-f", PF_ANCHOR_FILE], check=False)


_DEF_PORTS = {80, 443}

def resolve_ips(domains: List[str]) -> Set[str]:
    ips: Set[str] = set()
    for d in domains:
        d = d.strip()
        if not d: continue
        try:
            # get IPv4 only (AF_INET). IPv6 pf table is also fine if present, but blocking IPv4 already adds friction
            infos = socket.getaddrinfo(d, None, family=socket.AF_INET)
            for fam, stype, proto, canon, sockaddr in infos:
                ip = sockaddr[0]
                if ip and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
                    ips.add(ip)
        except socket.gaierror:
            pass
    return ips

# ---------- launchd ----------

def write_daemon_plist(partC_b64: str, python_path: str|None=None):
    """Write the LaunchDaemon plist with a stable Python path and correct ownership."""
    # Choose a stable Python interpreter for launchd
    candidates = []
    if python_path:
        candidates.append(python_path)
    if sys.executable:
        candidates.append(sys.executable)
    candidates += [
        "/usr/bin/python3",
        "/opt/homebrew/bin/python3",
        "/usr/local/bin/python3",
    ]
    program = None
    for c in candidates:
        if c and os.path.exists(c):
            program = c
            break
    if not program:
        program = "/usr/bin/python3"  # avoid /usr/bin/env for LaunchDaemons

    script_path = os.path.realpath(sys.argv[0])

    plist = f"""
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{program}</string>
    <string>{script_path}</string>
    <string>{DAEMON_ARG}</string>
    <string>--sbC={partC_b64}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{LOG_DIR}/siteblocker.log</string>
  <key>StandardErrorPath</key><string>{LOG_DIR}/siteblocker.err</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
"""
    atomic_write(PLIST_PATH, plist, mode=0o644)
    # Ensure correct ownership for LaunchDaemons
    try:
        os.chown(PLIST_PATH, 0, 0)  # root:wheel (wheel is gid 0)
    except PermissionError:
        pass


def launchctl_load():
    """Load (or reload) the daemon using modern launchctl verbs.
    We first try bootout+bootstrap (macOS 10.13+). Fall back to legacy load/unload.
    Suppress stdout so harmless warnings don't show up.
    """
    # modern path
    run(["/bin/launchctl", "bootout", "system", f"system/{LAUNCHD_LABEL}"], check=False, capture=True)
    run(["/bin/launchctl", "bootout", "system", PLIST_PATH], check=False, capture=True)
    run(["/bin/launchctl", "bootstrap", "system", PLIST_PATH], check=False, capture=True)
    run(["/bin/launchctl", "enable", f"system/{LAUNCHD_LABEL}"], check=False, capture=True)
    run(["/bin/launchctl", "kickstart", "-k", f"system/{LAUNCHD_LABEL}"], check=False, capture=True)

    # legacy fallback (older macOS)
    run(["/bin/launchctl", "unload", PLIST_PATH], check=False, capture=True)
    try:
        run(["/bin/launchctl", "load", PLIST_PATH], check=True, capture=True)
    except Exception:
        pass


def launchctl_unload():
    # modern
    run(["/bin/launchctl", "bootout", "system", f"system/{LAUNCHD_LABEL}"], check=False, capture=True)
    run(["/bin/launchctl", "bootout", "system", PLIST_PATH], check=False, capture=True)
    # legacy
    run(["/bin/launchctl", "unload", PLIST_PATH], check=False, capture=True)

# ---------- Core logic ----------

def ensure_installed(create_new_token: bool = False, python_path: str|None=None):
    macos_guard()
    require_root()

    # Create dirs and base files
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)

    state = load_json(STATE_PATH, {"active": False, "until": 0, "domains": []})
    cfg = load_json(CONFIG_PATH, {"poll_seconds": 15})

    # Generate stop token
    partC_b64 = ""
    if create_new_token or not os.path.exists(SECRET_META_PATH):
        clear, partC = TokenManager.generate_and_store_new()
        partC_b64 = base64.b64encode(partC.encode()).decode()
        # Manual mode: no daemon plist
        print("[i] Manual mode: no LaunchDaemon will be installed.")
        msg = f"""
========= IMPORTANT: SAVE THIS =========
SiteBlocker STOP TOKEN (split in 3 parts):
  - Part A (base64) file: {TokenManager.PART_A_PATH}
  - Part B (xattr) key: com.siteblocker.partB on {PF_ANCHOR_FILE}
  - Part C (xattr) key: com.siteblocker.partC on {HOSTS_PATH}

To reconstruct the token:
  token = base64decode(A) + base64decode(B) + base64decode(C)
Then stop early with: sudo ./siteblocker.py stop --token <token>
After expiry, just run: sudo ./siteblocker.py repair
=======================================
"""
        print(msg)
    else:
        print("[i] Manual mode active; reusing existing token metadata.")
    save_json(STATE_PATH, state)
    save_json(CONFIG_PATH, cfg)


# Apply/clear all enforcement layers

def apply_all(domains: List[str]):
    if not domains:
        return
    hosts_apply(domains)
    ips = resolve_ips(domains)
    pf_enable()
    pf_anchor_write_and_load(ips)


def clear_all():
    hosts_clear()
    # Clear pf table/file (keep anchor but empty list)
    atomic_write(PF_TABLE_FILE, "\n", mode=0o644)
    pf_anchor_write_and_load(set())


# ---------- Daemon loop ----------

def daemon_loop():
    # The daemon runs as root via launchd and periodically re-asserts block if active
    while True:
        try:
            state = load_json(STATE_PATH, {"active": False, "until": 0, "domains": []})
            cfg = load_json(CONFIG_PATH, {"poll_seconds": 15})
            poll = max(5, int(cfg.get("poll_seconds", 15)))

            now = now_ts()
            if state.get("active") and now < int(state.get("until", 0)):
                # enforce
                apply_all(state.get("domains", []))
            else:
                # not active — ensure cleared but do it sparingly to avoid churn
                clear_all()
                state["active"] = False
                save_json(STATE_PATH, state)

        except Exception as e:
            try:
                with open(f"{LOG_DIR}/siteblocker.err", "a") as f:
                    f.write(f"{dt.datetime.now()}: {e}\n")
            except Exception:
                pass
        time.sleep(poll)

# ---------- CLI commands ----------

def cmd_doctor(args):
    """Diagnose launchd issues and attempt auto-fix without crashing on weird/binary plists."""
    require_root()

    # 1) Validate plist exists and is well-formed (according to plutil)
    if not os.path.exists(PLIST_PATH):
        print(f"[!] Missing plist: {PLIST_PATH}. Reinstall with: sudo python3 {os.path.basename(sys.argv[0])} install")
        return
    run(["/usr/bin/plutil", "-lint", PLIST_PATH], check=False)

    # 2) Ownership & perms
    try:
        st = os.stat(PLIST_PATH)
        if st.st_uid != 0 or st.st_gid != 0:
            print("[!] Fixing plist ownership to root:wheel …")
            run(["/usr/sbin/chown", "root:wheel", PLIST_PATH], check=False)
        run(["/bin/chmod", "644", PLIST_PATH], check=False)
    except Exception as e:
        print(f"[i] Could not adjust ownership/perms: {e}")

    # 3) Read ProgramArguments safely via plutil->json (handles binary plists)
    args_pa = []
    partC = ""
    try:
        out = run(["/usr/bin/plutil", "-convert", "json", "-o", "-", PLIST_PATH], check=True, capture=True)
        data = json.loads(out)
        args_pa = data.get("ProgramArguments", []) or []
        for s in args_pa:
            m = re.match(r"--sbC=(.+)", s)
            if m:
                partC = m.group(1)
                break
    except Exception as e:
        print(f"[i] plutil json read failed (non-fatal): {e}")
        # last resort: try plistlib
        try:
            import plistlib
            with open(PLIST_PATH, 'rb') as f:
                pl = plistlib.load(f)
            args_pa = pl.get("ProgramArguments", []) or []
            for s in args_pa:
                m = re.match(r"--sbC=(.+)", s)
                if m:
                    partC = m.group(1)
                    break
        except Exception as e2:
            print(f"[i] plistlib read failed too (non-fatal): {e2}")

    # 4) Validate python/script paths, optionally override python via --python
    chosen_py = getattr(args, 'python', None)
    if not chosen_py:
        fallbacks = (args_pa[:1] if args_pa else []) + [
            "/usr/bin/python3", "/opt/homebrew/bin/python3", "/usr/local/bin/python3", sys.executable
        ]
        for cand in fallbacks:
            if cand and os.path.exists(cand):
                chosen_py = cand
                break
    if not chosen_py or not os.path.exists(chosen_py):
        chosen_py = "/usr/bin/python3"

    script_path_ok = False
    if len(args_pa) >= 2 and os.path.exists(args_pa[1]):
        script_path_ok = True

    if not args_pa or not os.path.exists(chosen_py) or not script_path_ok:
        print("[i] Rewriting plist with a stable python and script path …")
        if not partC:
            partC = base64.b64encode(secrets.token_bytes(6)).decode()
        write_daemon_plist(partC, python_path=chosen_py)

    # 5) Bootstrap + kickstart
    launchctl_load()

    # 6) Print service state
    out = run(["/bin/launchctl", "print", f"system/{LAUNCHD_LABEL}"], check=False, capture=True)
    print(out or "[i] launchctl print returned no data; service may not be loaded.")

# ---------- CLI commands ----------

def cmd_repair(args):
    """Reconcile on-disk state with enforcement. Manual mode (no launchd)."""
    require_root()
    state = load_json(STATE_PATH, {"active": False, "until": 0, "domains": []})
    now = now_ts()
    until = int(state.get("until", 0))

    if state.get("active") and now >= until:
        clear_all()
        state["active"] = False
        state["until"] = 0
        save_json(STATE_PATH, state)
        print("[+] Expired block cleaned up.")
    elif state.get("active") and now < until:
        apply_all(state.get("domains", []))
        print("[+] Reapplied current block.")
    else:
        clear_all()
        print("[+] No active block. System enforcement cleared.")

# ---------- CLI commands ----------

def cmd_install(args):
    ensure_installed(create_new_token=True, python_path=getattr(args, 'python', None))
    print("[+] Installed daemon and generated a new stop token (split across locations). Save the instructions above.")


def cmd_block(args):
    ensure_installed(create_new_token=False)
    require_root()

    minutes = int(args.minutes)
    if minutes <= 0:
        print("[!] minutes must be > 0")
        sys.exit(1)

    # domains
    domains: List[str] = []
    if args.sites:
        for s in args.sites.split(","):
            s = s.strip()
            if s:
                domains.append(s)
    if args.sites_file:
        with open(args.sites_file, "r") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    domains.append(s)
    domains = sorted(set(domains))
    if not domains:
        print("[!] No domains provided.")
        sys.exit(1)

    state = load_json(STATE_PATH, {"active": False, "until": 0, "domains": []})
    until = now_ts() + minutes*60
    state.update({"active": True, "until": until, "domains": domains})
    save_json(STATE_PATH, state)

    # Manual mode: just apply enforcement once
    apply_all(domains)

    print(f"[+] Blocking {len(domains)} site(s) for {pretty_duration(minutes*60)} (until {dt.datetime.fromtimestamp(until).isoformat(timespec='minutes')}).")
    print("    After it expires, run: sudo python3 siteblocker.py repair")
    print("    Tip: status: ./siteblocker.py status")


def cmd_extend(args):
    require_root()
    add_min = int(args.minutes)
    state = load_json(STATE_PATH, {"active": False, "until": 0, "domains": []})
    if not state.get("active"):
        print("[!] No active block.")
        sys.exit(1)
    state["until"] = int(state.get("until", now_ts())) + add_min*60
    save_json(STATE_PATH, state)
    print(f"[+] Extended by {add_min} minutes. New end: {dt.datetime.fromtimestamp(state['until']).isoformat(timespec='minutes')}")


def _reconstruct_token_from_parts() -> str|None:
    # Helper to reconstruct if user forgot: reads all 3 parts and returns clear token
    try:
        with open(TokenManager.PART_A_PATH, "r") as f:
            partA = base64.b64decode(f.read().strip()).decode()
    except Exception:
        partA = ""
    partB = ""
    try:
        out = run([XATTR_TOOL, "-p", TokenManager.XATTR_KEY, PF_ANCHOR_FILE], check=False, capture=True)
        if out:
            partB = base64.b64decode(out.strip()).decode()
        else:
            with open(f"{BASE_DIR}/partB.b64", "r") as f:
                partB = base64.b64decode(f.read().strip()).decode()
    except Exception:
        try:
            with open(f"{BASE_DIR}/partB.b64", "r") as f:
                partB = base64.b64decode(f.read().strip()).decode()
        except Exception:
            partB = ""
    partC = ""
    try:
        out = run([XATTR_TOOL, "-p", TokenManager.XATTR_KEY_C, HOSTS_PATH], check=False, capture=True)
        if out:
            partC = base64.b64decode(out.strip()).decode()
        else:
            with open(f"{BASE_DIR}/partC.b64", "r") as f:
                partC = base64.b64decode(f.read().strip()).decode()
    except Exception:
        try:
            with open(f"{BASE_DIR}/partC.b64", "r") as f:
                partC = base64.b64decode(f.read().strip()).decode()
        except Exception:
            partC = ""
    token = partA + partB + partC
    return token if token else None


def cmd_stop(args):
    require_root()
    token = args.token or ""
    if not token:
        token = _reconstruct_token_from_parts() or ""

    if not token or not TokenManager.verify(token):
        print("[!] Invalid or missing token. To recover, collect parts A/B/C as shown during install.")
        sys.exit(1)

    state = load_json(STATE_PATH, {"active": False, "until": 0, "domains": []})
    state.update({"active": False, "until": 0})
    save_json(STATE_PATH, state)

    clear_all()

    print("[+] Block disabled. You can re-enable later with `block`.")


def cmd_status(args):
    state = load_json(STATE_PATH, {"active": False, "until": 0, "domains": []})
    now = now_ts()
    active_flag = bool(state.get("active"))
    until = int(state.get("until", 0))
    active_now = active_flag and now < until

    if active_now:
        rem = max(0, until - now)
        print(f"Active: YES | Remaining: {pretty_duration(rem)} | Domains: {len(state.get('domains', []))}")
        print(", ".join(state.get("domains", [])[:20]) + (" ..." if len(state.get("domains", []))>20 else ""))
    else:
        if active_flag and now >= until:
            print("Expired: run: sudo python3 siteblocker.py repair (this clears hosts/pf and flips state)")
        else:
            print("Active: NO")



def cmd_add_sites(args):
    require_root()
    state = load_json(STATE_PATH, {"active": False, "until": 0, "domains": []})
    if not state.get("active"):
        print("[!] No active block. Use `block` first.")
        sys.exit(1)
    new = {s.strip() for s in args.sites.split(",") if s.strip()}
    domains = sorted(set(state.get("domains", [])) | new)
    state["domains"] = domains
    save_json(STATE_PATH, state)
    apply_all(domains)
    print(f"[+] Added {len(new)} site(s). Now blocking {len(domains)} total.")


def cmd_remove_sites(args):
    require_root()
    state = load_json(STATE_PATH, {"active": False, "until": 0, "domains": []})
    old = set(state.get("domains", []))
    if not old:
        print("[!] No domains configured.")
        sys.exit(1)
    to_remove = {s.strip() for s in args.sites.split(",") if s.strip()}
    domains = sorted(list(old - to_remove))
    state["domains"] = domains
    save_json(STATE_PATH, state)
    if state.get("active"):
        apply_all(domains)
    print(f"[+] Removed {len(to_remove)}. Now {len(domains)} domain(s) configured.")


# ---------- Argparse ----------

def build_parser():
    p = argparse.ArgumentParser(description="macOS SiteBlocker (CLI + daemon)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("install", help="Install daemon and generate a new stop token")
    s.add_argument("--python", help="Absolute path to python3 for the daemon (e.g., /opt/homebrew/bin/python3)")
    s.set_defaults(func=cmd_install)

    s = sub.add_parser("block", help="Start/overwrite a block for N minutes with the given sites")
    s.add_argument("--minutes", required=True, help="Duration in minutes", type=int)
    s.add_argument("--sites", help="Comma-separated domains", default="")
    s.add_argument("--sites-file", help="Text file with one domain per line")
    s.set_defaults(func=cmd_block)

    s = sub.add_parser("extend", help="Extend the current block by N minutes")
    s.add_argument("--minutes", required=True, type=int)
    s.set_defaults(func=cmd_extend)

    s = sub.add_parser("stop", help="Stop the block (requires token)")
    s.add_argument("--token", help="Full stop token (optional if you kept all 3 parts in place)")
    s.set_defaults(func=cmd_stop)

    s = sub.add_parser("status", help="Show current status")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("repair", help="Reconcile state with enforcement (force clear if expired)")
    s.set_defaults(func=cmd_repair)

    s = sub.add_parser("add-sites", help="Add domains to current block")
    s.add_argument("--sites", required=True)
    s.set_defaults(func=cmd_add_sites)

    s = sub.add_parser("remove-sites", help="Remove domains from current block")
    s.add_argument("--sites", required=True)
    s.set_defaults(func=cmd_remove_sites)

    s = sub.add_parser("doctor", help="Diagnose daemon issues and auto-fix common problems")
    s.add_argument("--python", help="Absolute path to python3 for the daemon (optional override)")
    s.set_defaults(func=cmd_doctor)

    # Hidden: daemon entrypoint
    p.add_argument(DAEMON_ARG, action="store_true", help=argparse.SUPPRESS)
    return p

# ---------- Main ----------

def main():
    p = build_parser()
    args = p.parse_args()

    if getattr(args, DAEMON_ARG.lstrip("-"), False):
        # run as daemon from launchd
        daemon_loop()
        return

    # Normal CLI commands
    if args.cmd:
        args.func(args)


if __name__ == "__main__":
    main()
