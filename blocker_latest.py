'''
This script is used to block websites from being accessed.

This is particularly for macos. So we would use /etc/hosts with immutable flag. The packet filter for dropping network outgoing to the blocked websites.
This will be a daemon process that runs in the background and blocks the websites. After the timer is completed, the websites will be unblocked, basically cleanup
for websites added in the /etc/hosts file and packet filter are removed. Also let's make such that daemon process cannot be killed by user.
'''

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import ipaddress
import json
import os
import platform
import re
import shlex
import signal
import socket
import subprocess
import sys
import time
from typing import Iterable, List, Optional, Sequence, Set, Tuple


# ---------- Constants ----------

HOSTS_FILE: str = "/etc/hosts"
HOSTS_START_MARK: str = "# WEBSITE_BLOCKER START"
HOSTS_END_MARK: str = "# WEBSITE_BLOCKER END"

PF_ANCHOR_NAME: str = "website-blocker"
PF_ANCHOR_FILE: str = f"/etc/pf.anchors/{PF_ANCHOR_NAME}"
PF_CONF_FILE: str = "/etc/pf.conf"

# State file to preserve original flags and context across a timed block
STATE_DIR: str = "/var/run/website_blocker"
STATE_FILE: str = f"{STATE_DIR}/state.json"
PID_FILE: str = f"{STATE_DIR}/daemon.pid"


# ---------- Utilities ----------

def is_macos() -> bool:
    return platform.system() == "Darwin"


def ensure_root() -> None:
    if os.geteuid() != 0:
        sys.exit("This command must be run as root. Try: sudo python3 website_blocker.py ...")


def run_cmd(cmd: Sequence[str], check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the CompletedProcess. Raise on failure if check is True."""
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed ({result.returncode}): {shlex.join(cmd)}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}")
    return result


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0]
    # Remove trailing dot
    if d.endswith('.'):
        d = d[:-1]
    return d


def is_subdomain(domain: str) -> bool:
      labels = domain.split('.')
      # 3+ labels = subdomain, but exclude www.example.com
      return len(labels) >= 3 and not domain.startswith('www.')


def expand_www_variants(domains: Iterable[str]) -> List[str]:
    expanded: Set[str] = set()
    for d in domains:
        nd = normalize_domain(d)
        if not nd:
            continue
        expanded.add(nd)
        # Add www variant for base domains only (avoid subdomains like blog.example.com)
        if "." in nd and not nd.startswith("www.") and not is_subdomain(nd):
            expanded.add(f"www.{nd}")
    return sorted(expanded)


def parse_duration_to_seconds(text: Optional[str]) -> Optional[int]:
    if text is None:
        return None
    s = str(text).strip().lower()
    if s.isdigit():
        # Interpret as minutes by default
        return int(s) * 60
    match = re.fullmatch(r"(\d+)([smhd])", s)
    if not match:
        raise ValueError("Invalid duration. Examples: 45m, 2h, 30s, 1d, or integer minutes like 25")
    value = int(match.group(1))
    unit = match.group(2)
    if unit == "s":
        return value
    if unit == "m":
        return value * 60
    if unit == "h":
        return value * 3600
    if unit == "d":
        return value * 86400
    raise ValueError("Unsupported duration unit")


def ensure_state_dir() -> None:
    os.makedirs(STATE_DIR, exist_ok=True)


def write_state(state: dict) -> None:
    ensure_state_dir()
    tmp_path = f"{STATE_FILE}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp_path, STATE_FILE)


def read_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def remove_state() -> None:
    with contextlib.suppress(FileNotFoundError):
        os.remove(STATE_FILE)


def write_pid_file(pid: int) -> None:
    ensure_state_dir()
    tmp_path = f"{PID_FILE}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(str(pid))
    os.replace(tmp_path, PID_FILE)


def read_pid_file() -> Optional[int]:
    try:
        with open(PID_FILE, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return int(content)
    except FileNotFoundError:
        return None
    except ValueError:
        return None


def remove_pid_file() -> None:
    with contextlib.suppress(FileNotFoundError):
        os.remove(PID_FILE)


def pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Unlikely as root; assume running
        return True


# ---------- /etc/hosts management ----------

def is_hosts_immutable() -> bool:
    try:
        # Use ls with uppercase -O to check file flags; look for uchg (user immutable) or schg (system immutable)
        res = run_cmd(["/bin/ls", "-lO", HOSTS_FILE], check=False)
        flags_line = (res.stdout + res.stderr)
        return " uchg" in flags_line or " schg" in flags_line
    except Exception:
        return False


def set_hosts_immutable(make_immutable: bool) -> None:
    if make_immutable:
        run_cmd(["/usr/bin/chflags", "uchg", HOSTS_FILE])
    else:
        # Clear both user and system immutable if possible
        run_cmd(["/usr/bin/chflags", "nouchg", HOSTS_FILE], check=False)
        run_cmd(["/usr/bin/chflags", "noschg", HOSTS_FILE], check=False)


def read_hosts() -> str:
    with open(HOSTS_FILE, "r", encoding="utf-8") as f:
        return f.read()


def write_hosts(content: str) -> None:
    temp = f"{HOSTS_FILE}.website_blocker.tmp"
    with open(temp, "w", encoding="utf-8") as f:
        f.write(content)
    try:
        os.replace(temp, HOSTS_FILE)
    except PermissionError:
        # Attempt to clear immutability and retry once
        with contextlib.suppress(Exception):
            set_hosts_immutable(False)
        os.replace(temp, HOSTS_FILE)


def remove_marked_block(text: str) -> Tuple[str, bool]:
    pattern = re.compile(
        rf"\n?{re.escape(HOSTS_START_MARK)}[\s\S]*?{re.escape(HOSTS_END_MARK)}\n?",
        re.MULTILINE,
    )
    new_text, n = pattern.subn("", text)
    return new_text, n > 0


def make_hosts_block(domains: Sequence[str]) -> str:
    lines = [
        HOSTS_START_MARK,
        f"# Added at {now_iso()} by website_blocker.py",
    ]
    for dom in domains:
        lines.append(f"127.0.0.1 {dom}")
        lines.append(f"::1 {dom}")
    lines.append(HOSTS_END_MARK)
    return "\n" + "\n".join(lines) + "\n"


def apply_hosts_block(domains: Sequence[str], make_immutable: bool) -> dict:
    prev_immutable = is_hosts_immutable()
    if prev_immutable:
        # Temporarily unlock to modify
        set_hosts_immutable(False)
    original = read_hosts()
    without_block, _ = remove_marked_block(original)
    updated = without_block.rstrip("\n") + make_hosts_block(domains)
    write_hosts(updated)
    if make_immutable:
        set_hosts_immutable(True)
    return {"hosts_immutable_before": prev_immutable}


def remove_hosts_block(restore_immutable: Optional[bool]) -> None:
    prev_immutable = is_hosts_immutable()
    if prev_immutable:
        set_hosts_immutable(False)
    content = read_hosts()
    new_content, removed = remove_marked_block(content)
    if removed:
        write_hosts(new_content)
    # Restore immutable state if instructed
    if restore_immutable is not None:
        set_hosts_immutable(restore_immutable)
    else:
        # If we unlocked to edit and previously immutable, set back
        if prev_immutable:
            set_hosts_immutable(True)


# ---------- PF (Packet Filter) management ----------

def pf_is_enabled() -> bool:
    res = run_cmd(["/sbin/pfctl", "-s", "info"], check=False)
    # Look for "Status: Enabled"
    return "Status: Enabled" in res.stdout


def pf_enable() -> None:
    if not pf_is_enabled():
        run_cmd(["/sbin/pfctl", "-E"])  # Enable packet filter


def pf_anchor_lines() -> str:
    return (
        f"\n# website_blocker anchor (added {now_iso()})\n"
        f"anchor \"{PF_ANCHOR_NAME}\"\n"
        f"load anchor \"{PF_ANCHOR_NAME}\" from \"{PF_ANCHOR_FILE}\"\n"
    )


def pf_conf_contains_anchor() -> bool:
    try:
        with open(PF_CONF_FILE, "r", encoding="utf-8") as f:
            content = f.read()
        return PF_ANCHOR_NAME in content and PF_ANCHOR_FILE in content
    except FileNotFoundError:
        return False


def pf_ensure_anchor_in_pfconf() -> bool:
    """Ensure pf.conf contains the anchor include. Returns True if we modified it."""
    try:
        with open(PF_CONF_FILE, "r", encoding="utf-8") as f:
            content = f.read()
    except FileNotFoundError:
        raise RuntimeError("/etc/pf.conf not found; PF not available on this system")

    if PF_ANCHOR_NAME in content and PF_ANCHOR_FILE in content:
        return False

    # Append our anchor lines to the end of the file
    new_content = content.rstrip("\n") + pf_anchor_lines()
    temp = f"{PF_CONF_FILE}.website_blocker.tmp"
    with open(temp, "w", encoding="utf-8") as f:
        f.write(new_content)
    os.replace(temp, PF_CONF_FILE)
    return True


def pf_write_anchor_rules(ipv4_list: Sequence[str], ipv6_list: Sequence[str]) -> None:
    lines: List[str] = []
    lines.append(f"# website_blocker anchor rules - generated {now_iso()}")
    lines.append("set skip on lo0")

    v4 = sorted({ip for ip in ipv4_list if ip})
    v6 = sorted({ip for ip in ipv6_list if ip})

    if v4:
        joined = ", ".join(v4)
        lines.append(f"block drop out quick inet to {{ {joined} }}")
    if v6:
        joined6 = ", ".join(v6)
        lines.append(f"block drop out quick inet6 to {{ {joined6} }}")

    content = "\n".join(lines) + "\n"

    # Ensure directory exists
    anchor_dir = os.path.dirname(PF_ANCHOR_FILE)
    os.makedirs(anchor_dir, exist_ok=True)
    temp = f"{PF_ANCHOR_FILE}.tmp"
    with open(temp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(temp, PF_ANCHOR_FILE)


def pf_load_rules() -> None:
    # Load/refresh the main pf.conf (which includes our anchor) and specifically refresh the anchor as well
    run_cmd(["/sbin/pfctl", "-f", PF_CONF_FILE])
    run_cmd(["/sbin/pfctl", "-a", PF_ANCHOR_NAME, "-f", PF_ANCHOR_FILE])


def pf_clear_anchor_rules() -> None:
    # Overwrite anchor file with a harmless comment
    os.makedirs(os.path.dirname(PF_ANCHOR_FILE), exist_ok=True)
    with open(PF_ANCHOR_FILE, "w", encoding="utf-8") as f:
        f.write(f"# website_blocker anchor cleared at {now_iso()}\n")
    with contextlib.suppress(Exception):
        run_cmd(["/sbin/pfctl", "-a", PF_ANCHOR_NAME, "-f", PF_ANCHOR_FILE])
    with contextlib.suppress(Exception):
        run_cmd(["/sbin/pfctl", "-f", PF_CONF_FILE])


def resolve_domain_ips(domains: Sequence[str]) -> Tuple[List[str], List[str]]:
    ipv4: Set[str] = set()
    ipv6: Set[str] = set()
    for dom in domains:
        try:
            infos = socket.getaddrinfo(dom, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            continue
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                ipv4.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ip = sockaddr[0].split('%')[0]  # strip zone index
                ipv6.add(ip)
    # Filter out local addresses to avoid self-blocking
    ipv4 = {ip for ip in ipv4 if not ipaddress.ip_address(ip).is_loopback}
    ipv6 = {ip for ip in ipv6 if not ipaddress.ip_address(ip).is_loopback}
    return sorted(ipv4), sorted(ipv6)


def flush_dns_cache() -> None:
    # Best-effort flush across macOS versions; ignore failures
    run_cmd(["/usr/bin/dscacheutil", "-flushcache"], check=False)
    run_cmd(["/usr/bin/killall", "-HUP", "mDNSResponder"], check=False)
    run_cmd(["/usr/bin/killall", "mDNSResponderHelper"], check=False)


def humanize_seconds(total_seconds: int) -> str:
    seconds = max(0, int(total_seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    if minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def compute_remaining_seconds_from_state(state: dict) -> Optional[int]:
    try:
        start_iso = state.get("start_time")
        duration = int(state.get("duration_seconds")) if state.get("duration_seconds") is not None else None
        if not start_iso or duration is None:
            return None
        start_dt = dt.datetime.fromisoformat(start_iso)
        now_dt = dt.datetime.now().astimezone()
        # If start_dt has no tzinfo, assume local timezone
        if start_dt.tzinfo is None:
            start_dt = start_dt.astimezone()
        end_dt = start_dt + dt.timedelta(seconds=duration)
        remaining = (end_dt - now_dt).total_seconds()
        return max(0, int(remaining))
    except Exception:
        return None


# ---------- Core operations ----------

@dataclasses.dataclass
class BlockOptions:
    domains: List[str]
    use_hosts: bool = True
    make_hosts_immutable: bool = True
    use_pf: bool = True
    duration_seconds: Optional[int] = None
    


def do_block(opts: BlockOptions) -> None:
    if not is_macos():
        sys.exit("This script supports only macOS (Darwin)")
    ensure_root()
    if not opts.domains:
        sys.exit("No domains provided to block. Use --domains or --file")
    if not opts.duration_seconds or opts.duration_seconds <= 0:
        sys.exit("--duration is required and must be > 0. Example: -t 45m")

    # Prevent overlapping blocks if a daemon is already running
    existing_pid = read_pid_file()
    if existing_pid and pid_is_running(existing_pid):
        existing_state = read_state()
        rem = compute_remaining_seconds_from_state(existing_state) or 0
        sys.exit(f"A block daemon is already running (pid {existing_pid}), remaining {humanize_seconds(rem)}")
    elif existing_pid and not pid_is_running(existing_pid):
        remove_pid_file()

    normalized_domains = expand_www_variants(opts.domains)

    state: dict = {
        "start_time": now_iso(),
        "domains": normalized_domains,
        "use_hosts": opts.use_hosts,
        "use_pf": opts.use_pf,
        "duration_seconds": opts.duration_seconds,
    }

    if opts.use_hosts:
        hosts_info = apply_hosts_block(normalized_domains, make_immutable=opts.make_hosts_immutable)
        state.update(hosts_info)

    if opts.use_pf:
        v4, v6 = resolve_domain_ips(normalized_domains)
        pf_enable()
        modified_pfconf = pf_ensure_anchor_in_pfconf()
        pf_write_anchor_rules(v4, v6)
        pf_load_rules()
        state.update({
            "pf_modified_pfconf": modified_pfconf,
            "pf_ipv4": v4,
            "pf_ipv6": v6,
        })

    write_state(state)
    # Ensure quick effect
    flush_dns_cache()

    daemonize_and_schedule_unblock(opts.duration_seconds)
    print(f"Blocking {len(normalized_domains)} domains for {opts.duration_seconds} seconds (detached)")

def daemonize_and_schedule_unblock(after_seconds: int) -> None:
    # Double-fork daemonization
    pid = os.fork()
    if pid > 0:
        # Parent exits
        os._exit(0)
    os.setsid()
    pid = os.fork()
    if pid > 0:
        os._exit(0)

    # Redirect stdio to /dev/null
    with open('/dev/null', 'rb', 0) as devnull_in, open('/dev/null', 'ab', 0) as devnull_out:
        os.dup2(devnull_in.fileno(), sys.stdin.fileno())
        os.dup2(devnull_out.fileno(), sys.stdout.fileno())
        os.dup2(devnull_out.fileno(), sys.stderr.fileno())

    # Ignore termination signals to make it harder to kill (not foolproof)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    # Record daemon PID
    try:
        write_pid_file(os.getpid())
    except Exception:
        pass

    time.sleep(after_seconds)
    # Run unblock in this process
    try:
        do_unblock()
    except Exception:
        # Best-effort; nothing else to do in daemon context
        pass
    finally:
        with contextlib.suppress(Exception):
            remove_pid_file()
        os._exit(0)


def do_unblock() -> None:
    if not is_macos():
        sys.exit("This script supports only macOS (Darwin)")
    ensure_root()

    state = read_state()
    use_hosts = bool(state.get("use_hosts", True))
    use_pf = bool(state.get("use_pf", True))
    restore_immutable: Optional[bool] = None
    if "hosts_immutable_before" in state:
        restore_immutable = bool(state["hosts_immutable_before"])  # restore prior immutable state

    if use_hosts:
        remove_hosts_block(restore_immutable=restore_immutable)

    if use_pf:
        pf_clear_anchor_rules()

    # Flush DNS caches so changes take effect immediately
    flush_dns_cache()

    remove_state()
    print("Unblocked websites and cleaned up hosts and PF rules.")


def do_status() -> None:
    hosts_content = read_hosts()
    has_block = HOSTS_START_MARK in hosts_content and HOSTS_END_MARK in hosts_content
    hosts_flag = is_hosts_immutable()
    pf_enabled = pf_is_enabled()
    pf_rules = run_cmd(["/sbin/pfctl", "-a", PF_ANCHOR_NAME, "-s", "rules"], check=False)
    has_pf_rules = bool(pf_rules.stdout.strip()) and not pf_rules.stdout.strip().startswith("No ALTQ support")
    pid = read_pid_file()
    pid_running = bool(pid and pid_is_running(pid))
    state = read_state()
    remaining = compute_remaining_seconds_from_state(state) if state else None

    print("Status:")
    print(f"- hosts block present: {has_block}")
    print(f"- hosts immutable: {hosts_flag}")
    print(f"- pf enabled: {pf_enabled}")
    print(f"- pf anchor rules present: {has_pf_rules}")
    print(f"- daemon pid: {pid if pid else 'none'} (running: {pid_running})")
    if remaining is not None:
        print(f"- remaining: {humanize_seconds(remaining)}")


# ---------- CLI parsing ----------

def read_domains_from_file(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f]
    return [d for d in domains if d and not d.startswith("#")]


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Website blocker for macOS using /etc/hosts and PF (packet filter)")
    sub = p.add_subparsers(dest="command", required=True)

    # block
    pb = sub.add_parser("block", help="Block the given domains")
    pb.add_argument("--domains", "-d", nargs="*", default=[], help="Domains to block (space-separated)")
    pb.add_argument("--file", "-f", help="File containing domains (one per line)")
    pb.add_argument("--duration", "-t", required=True, help="Duration (e.g., 25m, 2h). Required; auto-unblocks via daemon")
    pb.add_argument("--hosts", dest="use_hosts", action="store_true", help="Use /etc/hosts for blocking (default)")
    pb.add_argument("--no-hosts", dest="use_hosts", action="store_false", help="Do not modify /etc/hosts")
    pb.set_defaults(use_hosts=True)
    pb.add_argument("--immutable", dest="make_hosts_immutable", action="store_true", help="Set /etc/hosts immutable during block (default)")
    pb.add_argument("--no-immutable", dest="make_hosts_immutable", action="store_false", help="Do not set /etc/hosts immutable")
    pb.set_defaults(make_hosts_immutable=True)
    pb.add_argument("--pf", dest="use_pf", action="store_true", help="Use PF to drop outgoing packets to resolved IPs (default)")
    pb.add_argument("--no-pf", dest="use_pf", action="store_false", help="Do not use PF")
    pb.set_defaults(use_pf=True)
    

    # status
    ps = sub.add_parser("status", help="Show current block status")
    # no extra args

    # unblock
    pu = sub.add_parser("unblock", help="Unblock and clean up immediately (hosts and PF)")
    # no extra args

    return p


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command == "block":
        # Check if a block is already in progress
        state = read_state()
        remaining = compute_remaining_seconds_from_state(state) if state else None
        if remaining is not None and remaining > 0:
            sys.exit(f"Timer not finished: {humanize_seconds(remaining)} remaining. Try again later")

        # Parse domains and duration
        domains: List[str] = list(args.domains or [])
        if args.file:
            domains.extend(read_domains_from_file(args.file))
        if not domains:
            parser.error("No domains provided. Use --domains or --file")
        duration_seconds = parse_duration_to_seconds(args.duration) if args.duration else None
        opts = BlockOptions(
            domains=domains,
            use_hosts=bool(args.use_hosts),
            make_hosts_immutable=bool(args.make_hosts_immutable),
            use_pf=bool(args.use_pf),
            duration_seconds=duration_seconds,
        )
        do_block(opts)
        return

    if args.command == "status":
        do_status()
        return
    
    if args.command == "unblock":
        # By default, only allow when timer has completed
        state = read_state()
        remaining = compute_remaining_seconds_from_state(state) if state else None
        if remaining is not None and remaining > 0:
            sys.exit(f"Timer not finished: {humanize_seconds(remaining)} remaining. Try again later")
        do_unblock()
        return

    parser.error("Unknown command")


if __name__ == "__main__":
    main()

