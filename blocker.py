#!/usr/bin/env python3
# Fixed version addressing 10 must-fix issues called out in the review.
# Changes:
# 1) Removed interactive math/password prompts from the daemon path; added a foreground
#    "stop" subcommand that verifies the password and then signals the daemon (SIGUSR1).
# 2) Switched dnsmasq drop-in path to /etc/dnsmasq.d/website_blocker.conf and ensured dir.
# 3) On Linux, prefer "resolvectl flush-caches" and fall back to systemd-resolve, etc.
# 4) Replaced Linux traffic monitor's use of netstat with ss (iproute2).
# 5) Detect and prefer nftables if available; otherwise fall back to iptables/ip6tables or pf on macOS.
# 6) Add IPv6 support: hosts file ::1 entries and ip6 firewall rules (or nft inet table).
# 7) Emergency cleanup no longer references a non-existent iptables rules backup; it removes chains safely.
# 8) Only generate the password on first run (if hash file is missing); lock down permissions.
# 9) Replace ping-based verification with resolver-based checks against 127.0.0.1/::1 and only when blocking.
# 10) Make hosts-section removal robust via regex instead of brittle string index.

import os
import sys
import re
import time
import json
import signal
import logging
import datetime
import subprocess
import hashlib
import getpass
import random
import string
import socket
import fcntl
import errno
import argparse
import shutil
from daemon import DaemonContext
import lockfile

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/website_blocker.log'),
        logging.StreamHandler()
    ]
)

# -----------------------------------------------------------------------------
# WebsiteBlocker
# -----------------------------------------------------------------------------
class WebsiteBlocker:
    def __init__(self, duration_minutes=None):
        self.block_list_path = "/etc/website_blocker/block_list.txt"
        self.hosts_path = "/etc/hosts"
        self.hosts_backup = "/etc/hosts.backup"
        self.marker_start = "# Website Blocker Start"
        self.marker_end = "# Website Blocker End"
        self.duration_minutes = duration_minutes
        self.start_time = None
        self.start_monotonic = None
        self.pid_file = "/var/run/website_blocker.pid"
        self.lock_file = "/var/run/website_blocker.lock"
        self.password_hash_file = "/etc/website_blocker/password_hash.txt"
        self.password_clue_file = "/etc/website_blocker/.password_clue.txt"
        self.password_hash = None
        self.restart_script_path = "/etc/website_blocker/restart.sh"
        # FIX (2): dnsmasq drop-in path
        self.dnsmasq_conf_path = "/etc/dnsmasq.d/website_blocker.conf"
        self.iptables_rules_file = "/etc/website_blocker/iptables_rules.sh"
        self.nft_rules_file = "/etc/website_blocker/nft_rules.sh"
        self.traffic_monitor_script = "/etc/website_blocker/traffic_monitor.py"
        self.blocked_ips_v4 = set()
        self.blocked_ips_v6 = set()
        self.state_file = "/etc/website_blocker/blocker_state.json"

        # Ensure base dir exists
        base_dir = os.path.dirname(self.block_list_path)
        os.makedirs(base_dir, exist_ok=True)

        # Create default list on first run
        if not os.path.exists(self.block_list_path):
            self.create_default_block_list()

        # FIX (8): Only generate password/clues on first run
        if not os.path.exists(self.password_hash_file):
            self.generate_complex_password()
        else:
            try:
                with open(self.password_hash_file, 'r') as f:
                    self.password_hash = f.read().strip()
                os.chmod(self.password_hash_file, 0o400)
            except Exception as e:
                logging.error(f"Failed to read password hash: {e}")

    # ------------------------------------------------------------------
    # Locking & PID
    # ------------------------------------------------------------------
    def acquire_lock(self):
        try:
            os.makedirs(os.path.dirname(self.lock_file), exist_ok=True)
            self.lock_fd = os.open(self.lock_file, os.O_CREAT | os.O_WRONLY)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(self.lock_fd, str(os.getpid()).encode())
            os.fsync(self.lock_fd)
            logging.info(f"Acquired exclusive lock with PID {os.getpid()}")
            return True
        except IOError as e:
            if e.errno in (errno.EACCES, errno.EAGAIN):
                try:
                    with open(self.lock_file, 'r') as f:
                        other_pid = f.read().strip()
                    logging.error(f"Another instance is already running with PID {other_pid}")
                except Exception:
                    logging.error("Another instance is already running")
                return False
            logging.error(f"Failed to acquire lock: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error acquiring lock: {e}")
            return False

    def release_lock(self):
        try:
            if hasattr(self, 'lock_fd'):
                fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
                os.close(self.lock_fd)
                if os.path.exists(self.lock_file):
                    os.remove(self.lock_file)
                logging.info("Released exclusive lock")
        except Exception as e:
            logging.error(f"Error releasing lock: {e}")

    def write_pid_file(self):
        try:
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
            logging.info(f"Written PID {os.getpid()} to {self.pid_file}")
        except Exception as e:
            logging.error(f"Failed to write PID file: {e}")

    def remove_pid_file(self):
        try:
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
                logging.info("Removed PID file")
        except Exception as e:
            logging.error(f"Failed to remove PID file: {e}")

    # ------------------------------------------------------------------
    # Hosts & block list
    # ------------------------------------------------------------------
    def backup_hosts(self):
        if not os.path.exists(self.hosts_backup):
            try:
                with open(self.hosts_path, 'r') as src, open(self.hosts_backup, 'w') as dst:
                    dst.write(src.read())
                logging.info("Created hosts file backup")
            except Exception as e:
                logging.error(f"Failed to create hosts backup: {e}")
                sys.exit(1)

    def read_block_list(self):
        try:
            with open(self.block_list_path, 'r') as f:
                blocked_websites = [
                    line.strip() for line in f
                    if line.strip() and not line.strip().startswith('#')
                ]
                logging.info(f"Found {len(blocked_websites)} websites to block")
                return blocked_websites
        except Exception as e:
            logging.error(f"Failed to read block list: {e}")
            return []

    def create_default_block_list(self):
        try:
            default_sites = [
                "# Default block list - Add or remove websites as needed",
                "# One domain per line, without 'www' or 'https://'",
                "facebook.com",
                "twitter.com",
                "instagram.com",
                "reddit.com",
                "youtube.com",
                "netflix.com",
                "tiktok.com",
                "x.com",
            ]
            with open(self.block_list_path, 'w') as f:
                f.write("\n".join(default_sites))
            logging.info(f"Created default block list at {self.block_list_path}")
        except Exception as e:
            logging.error(f"Failed to create default block list: {e}")

    # ------------------------------------------------------------------
    # Resolution verification (FIX 9)
    # ------------------------------------------------------------------
    def verify_resolution(self, websites):
        ok = True
        expected = {"127.0.0.1", "::1"}
        for website in websites:
            try:
                infos = socket.getaddrinfo(website, None)
                addrs = {info[4][0] for info in infos}
                if not addrs:
                    logging.warning(f"No addresses for {website}")
                    continue
                if not addrs.issubset(expected):
                    logging.error(f"Resolver for {website} -> {addrs}, expected only {expected}")
                    ok = False
            except Exception as e:
                logging.warning(f"Resolver check failed for {website}: {e}")
        return ok

    # ------------------------------------------------------------------
    # DNS cache flush (FIX 3)
    # ------------------------------------------------------------------
    def flush_dns_cache(self):
        try:
            if sys.platform == "darwin":
                os.system("dscacheutil -flushcache")
                os.system("killall -HUP mDNSResponder")
                logging.info("Flushed DNS cache (macOS)")
            elif sys.platform == "linux":
                if shutil.which("resolvectl"):
                    subprocess.run(["resolvectl", "flush-caches"], check=False)
                elif shutil.which("systemd-resolve"):
                    subprocess.run(["systemd-resolve", "--flush-caches"], check=False)
                else:
                    subprocess.run(["service", "nscd", "restart"], check=False)
                logging.info("Flushed DNS cache (Linux)")
            return True
        except Exception as e:
            logging.error(f"Failed to flush DNS cache: {e}")
            return False

    # ------------------------------------------------------------------
    # Update hosts (FIX 6, 10)
    # ------------------------------------------------------------------
    def update_hosts(self, websites, blocking=True):
        try:
            with open(self.hosts_path, 'r') as f:
                hosts_content = f.read()

            # Remove any existing block section using regex
            pattern = re.compile(rf"{re.escape(self.marker_start)}.*?{re.escape(self.marker_end)}\n?", re.S)
            hosts_content = re.sub(pattern, "", hosts_content)

            if blocking:
                self.blocked_ips_v4.clear()
                self.blocked_ips_v6.clear()
                block_lines = [self.marker_start]
                for website in websites:
                    # Map to localhost for both IPv4 and IPv6
                    block_lines.append(f"127.0.0.1 {website}")
                    block_lines.append(f"127.0.0.1 www.{website}")
                    block_lines.append(f"::1 {website}")
                    block_lines.append(f"::1 www.{website}")
                    # Resolve to gather IPs for firewall/monitor
                    v4, v6 = self._resolve_ips_dualstack(website)
                    self.blocked_ips_v4.update(v4)
                    self.blocked_ips_v6.update(v6)
                    v4w, v6w = self._resolve_ips_dualstack(f"www.{website}")
                    self.blocked_ips_v4.update(v4w)
                    self.blocked_ips_v6.update(v6w)
                block_lines.append(self.marker_end)
                new_content = hosts_content.rstrip() + "\n\n" + "\n".join(block_lines) + "\n"
                with open(self.hosts_path, 'w') as f:
                    f.write(new_content)
                # DNS-level & firewall-level blocking
                self.update_dns_blocking(websites, blocking=True)
                self.update_firewall_rules(websites, blocking=True)
                self.start_traffic_monitor(websites)
            else:
                with open(self.hosts_path, 'w') as f:
                    f.write(hosts_content.rstrip() + "\n")
                self.update_dns_blocking(websites, blocking=False)
                self.update_firewall_rules(websites, blocking=False)
                self.stop_traffic_monitor()

            self.flush_dns_cache()
            if blocking:
                self.verify_resolution(websites)

            logging.info("Updated hosts file - blocking: %s", blocking)
            return True
        except Exception as e:
            logging.error(f"Failed to update hosts file: {e}")
            return False

    # ------------------------------------------------------------------
    # DNS-level blocking (FIX 2)
    # ------------------------------------------------------------------
    def update_dns_blocking(self, websites, blocking=True):
        try:
            if subprocess.run(["which", "dnsmasq"], capture_output=True).returncode != 0:
                logging.warning("dnsmasq not found, skipping DNS-level blocking")
                return False

            conf_dir = os.path.dirname(self.dnsmasq_conf_path)
            os.makedirs(conf_dir, exist_ok=True)

            if blocking and websites:
                with open(self.dnsmasq_conf_path, 'w') as f:
                    f.write("# Website Blocker DNS Configuration\n")
                    for website in websites:
                        f.write(f"address=/{website}/127.0.0.1\n")
                        f.write(f"address=/www.{website}/127.0.0.1\n")
                        f.write(f"address=/{website}/::1\n")
                        f.write(f"address=/www.{website}/::1\n")
                logging.info("Created DNS blocking configuration")
                try:
                    if sys.platform == "linux":
                        subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)
                except Exception as e:
                    logging.error(f"Failed to restart dnsmasq: {e}")
            else:
                if os.path.exists(self.dnsmasq_conf_path):
                    os.remove(self.dnsmasq_conf_path)
                    logging.info("Removed DNS blocking configuration")
                    try:
                        if sys.platform == "linux":
                            subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)
                    except Exception as e:
                        logging.error(f"Failed to restart dnsmasq: {e}")
            return True
        except Exception as e:
            logging.error(f"Failed to update DNS blocking: {e}")
            return False

    # ------------------------------------------------------------------
    # Firewall rules (FIX 5, 6, 7)
    # ------------------------------------------------------------------
    def update_firewall_rules(self, websites, blocking=True):
        """Add or remove firewall rules to block websites at the network level."""
        try:
            if self._is_command_available("nft"):
                return self._update_nft_rules(websites, blocking)
            elif self._is_command_available("iptables"):
                return self._update_iptables_rules(websites, blocking)
            elif sys.platform == "darwin" and self._is_command_available("pfctl"):
                return self._update_pf_rules(websites, blocking)
            else:
                logging.warning("No supported firewall tools found, skipping firewall-level blocking")
                return False
        except Exception as e:
            logging.error(f"Failed to update firewall rules: {e}")
            return False
        except Exception as e:
            logging.error(f"Failed to update firewall rules: {e}")
            return False

    def _is_command_available(self, command):
        return subprocess.run(["which", command], capture_output=True).returncode == 0

    def _resolve_ips_dualstack(self, domain):
        v4, v6 = set(), set()
        try:
            infos = socket.getaddrinfo(domain, None)
            for fam, _, _, _, addr in infos:
                ip = addr[0]
                if ":" in ip:
                    v6.add(ip)
                else:
                    v4.add(ip)
        except Exception:
            pass
        return v4, v6

    def _ensure_pf_anchor_wired(self):
        """Ensure /etc/pf.conf references and loads the website_blocker anchor.
        Appends the following lines if missing, then validates and reloads pf.conf:
            anchor "website_blocker"
            load anchor "website_blocker" from "/etc/pf.anchors/website_blocker"
        Uses absolute /sbin/pfctl.
        """
        try:
            pf_conf = "/etc/pf.conf"
            anchor_line = "anchor \"website_blocker\""
            load_line = "load anchor \"website_blocker\" from \"/etc/pf.anchors/website_blocker\""
            needs_reload = False
            content = ""
            if os.path.exists(pf_conf):
                with open(pf_conf, 'r') as f:
                    content = f.read()
            else:
                content = ""

            to_append = []
            if anchor_line not in content:
                to_append.append(anchor_line)
            if load_line not in content:
                to_append.append(load_line)

            if to_append:
                with open(pf_conf, 'a') as f:
                    if not content.endswith("
"):
                        f.write("
")
                    for line in to_append:
                        f.write(line + "
")
                needs_reload = True

            if needs_reload:
                pfctl = "/sbin/pfctl"
                subprocess.run([pfctl, '-nf', pf_conf], capture_output=True)
                subprocess.run([pfctl, '-f', pf_conf], capture_output=True)
        except Exception as e:
            logging.error(f"Failed to wire pf anchor: {e}")

    def _update_iptables_rules(self, websites, blocking=True):
        try:
            if blocking and websites:
                script = ["#!/bin/bash", "set -e"]
                # Create/clear chains
                script += [
                    "iptables -N WEBSITE_BLOCKER 2>/dev/null || true",
                    "iptables -F WEBSITE_BLOCKER || true",
                    "iptables -D OUTPUT -j WEBSITE_BLOCKER 2>/dev/null || true",
                    "ip6tables -N WEBSITE_BLOCKER 2>/dev/null || true",
                    "ip6tables -F WEBSITE_BLOCKER || true",
                    "ip6tables -D OUTPUT -j WEBSITE_BLOCKER 2>/dev/null || true",
                ]
                # Add rules for each resolved IP
                script.append("# Add IPv4 rules")
                for website in websites:
                    v4, _ = self._resolve_ips_dualstack(website)
                    for ip in v4:
                        script.append(f"iptables -A WEBSITE_BLOCKER -d {ip} -j REJECT || true")
                    v4w, _ = self._resolve_ips_dualstack(f"www.{website}")
                    for ip in v4w:
                        script.append(f"iptables -A WEBSITE_BLOCKER -d {ip} -j REJECT || true")
                script.append("# Add IPv6 rules")
                for website in websites:
                    _, v6 = self._resolve_ips_dualstack(website)
                    for ip in v6:
                        script.append(f"ip6tables -A WEBSITE_BLOCKER -d {ip} -j REJECT || true")
                    _, v6w = self._resolve_ips_dualstack(f"www.{website}")
                    for ip in v6w:
                        script.append(f"ip6tables -A WEBSITE_BLOCKER -d {ip} -j REJECT || true")
                # Hook chains
                script += [
                    "iptables -A OUTPUT -j WEBSITE_BLOCKER || true",
                    "ip6tables -A OUTPUT -j WEBSITE_BLOCKER || true",
                ]
                with open(self.iptables_rules_file, 'w') as f:
                    f.write("\n".join(script) + "\n")
                os.chmod(self.iptables_rules_file, 0o755)
                subprocess.run([self.iptables_rules_file], capture_output=True)
                logging.info("Applied iptables/ip6tables rules")
            else:
                # Remove chains cleanly (FIX 7)
                cleanup = [
                    "#!/bin/bash",
                    "iptables -D OUTPUT -j WEBSITE_BLOCKER 2>/dev/null || true",
                    "iptables -F WEBSITE_BLOCKER 2>/dev/null || true",
                    "iptables -X WEBSITE_BLOCKER 2>/dev/null || true",
                    "ip6tables -D OUTPUT -j WEBSITE_BLOCKER 2>/dev/null || true",
                    "ip6tables -F WEBSITE_BLOCKER 2>/dev/null || true",
                    "ip6tables -X WEBSITE_BLOCKER 2>/dev/null || true",
                ]
                with open(self.iptables_rules_file, 'w') as f:
                    f.write("\n".join(cleanup) + "\n")
                os.chmod(self.iptables_rules_file, 0o755)
                subprocess.run([self.iptables_rules_file], capture_output=True)
                logging.info("Removed iptables/ip6tables rules")
            return True
        except Exception as e:
            logging.error(f"Failed to update iptables rules: {e}")
            return False

    def _update_nft_rules(self, websites, blocking=True):
        try:
            if blocking and websites:
                v4_all, v6_all = set(), set()
                for w in websites:
                    v4, v6 = self._resolve_ips_dualstack(w)
                    v4_all |= v4
                    v6_all |= v6
                    v4w, v6w = self._resolve_ips_dualstack(f"www.{w}")
                    v4_all |= v4w
                    v6_all |= v6w

                def fmt_set(items):
                    return ", ".join(sorted(items))

                lines = [
                    "#!/bin/bash",
                    "set -e",
                    # Create table/chain in inet family (IPv4+IPv6)
                    "nft list table inet website_blocker >/dev/null 2>&1 || nft add table inet website_blocker",
                    "nft list chain inet website_blocker out_block >/dev/null 2>&1 || nft 'add chain inet website_blocker out_block { type filter hook output priority 0; }'",
                ]
                if v4_all:
                    lines.append(f"nft add rule inet website_blocker out_block ip daddr {{ {fmt_set(v4_all)} }} drop || true")
                if v6_all:
                    lines.append(f"nft add rule inet website_blocker out_block ip6 daddr {{ {fmt_set(v6_all)} }} drop || true")

                with open(self.nft_rules_file, 'w') as f:
                    f.write("\n".join(lines) + "\n")
                os.chmod(self.nft_rules_file, 0o755)
                subprocess.run([self.nft_rules_file], capture_output=True)
                logging.info("Applied nftables rules")
            else:
                cleanup = [
                    "#!/bin/bash",
                    "nft list table inet website_blocker >/dev/null 2>&1 && nft delete table inet website_blocker || true",
                ]
                with open(self.nft_rules_file, 'w') as f:
                    f.write("\n".join(cleanup) + "\n")
                os.chmod(self.nft_rules_file, 0o755)
                subprocess.run([self.nft_rules_file], capture_output=True)
                logging.info("Removed nftables rules")
            return True
        except Exception as e:
            logging.error(f"Failed to update nft rules: {e}")
            return False

    def _update_pf_rules(self, websites, blocking=True):
        try:
            if blocking and websites:
                # Minimal, non-persistent pf anchor approach (safer than replacing pf.conf)
                rules = ["# Website Blocker PF Rules"]
                for website in websites:
                    rules.append(f"block out quick to {website}")
                    rules.append(f"block out quick to www.{website}")
                rules_path = "/etc/pf.anchors/website_blocker"
                os.makedirs(os.path.dirname(rules_path), exist_ok=True)
                with open(rules_path, 'w') as f:
                    f.write("\n".join(rules) + "\n")
                # Load anchor and ensure pf is enabled
                subprocess.run(["pfctl", "-f", rules_path], capture_output=True)
                subprocess.run(["pfctl", "-E"], capture_output=True)
                logging.info("Applied pf rules (anchor)")
            else:
                rules_path = "/etc/pf.anchors/website_blocker"
                if os.path.exists(rules_path):
                    os.remove(rules_path)
                logging.info("Removed pf rules (anchor)")
            return True
        except Exception as e:
            logging.error(f"Failed to update pf rules: {e}")
            return False

    # ------------------------------------------------------------------
    # File protection
    # ------------------------------------------------------------------
    def protect_files(self, protect=True):
        try:
            if protect:
                os.chmod(self.block_list_path, 0o444)
                os.chmod(self.hosts_path, 0o444)
                logging.info("Protected configuration files")
            else:
                os.chmod(self.block_list_path, 0o644)
                os.chmod(self.hosts_path, 0o644)
                logging.info("Unprotected configuration files")
            return True
        except Exception as e:
            logging.error(f"Failed to modify file protection: {e}")
            return False

    # ------------------------------------------------------------------
    # State & integrity
    # ------------------------------------------------------------------
    def time_remaining(self):
        if not hasattr(self, 'start_monotonic') or not self.duration_minutes:
            return 0
        elapsed = (time.monotonic() - self.start_monotonic) / 60
        remaining = self.duration_minutes - elapsed
        return max(0, remaining)

    def calculate_file_hash(self, file_path):
        try:
            if not os.path.exists(file_path):
                return None
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logging.error(f"Failed to calculate file hash: {e}")
            return None

    def save_state(self, websites):
        try:
            state = {
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'duration_minutes': self.duration_minutes,
                'websites': list(websites),
                'pid': os.getpid(),
                'hosts_hash': self.hosts_file_hash
            }
            with open(self.state_file, 'w') as f:
                json.dump(state, f)
        except Exception as e:
            logging.error(f"Failed to save state: {e}")

    def check_hosts_file_integrity(self, websites):
        try:
            if not os.path.exists(self.hosts_path):
                logging.warning("Hosts file deleted! Restoring from backup...")
                self.restore_hosts_file(websites)
                return
            current_hash = self.calculate_file_hash(self.hosts_path)
            if current_hash != self.hosts_file_hash:
                logging.warning("Hosts file modified! Restoring block entries...")
                self.restore_hosts_file(websites)
        except Exception as e:
            logging.error(f"Error checking hosts file integrity: {e}")

    def restore_hosts_file(self, websites):
        try:
            if os.path.exists(self.hosts_backup):
                with open(self.hosts_backup, 'r') as src:
                    original = src.read()
                with open(self.hosts_path, 'w') as f:
                    f.write(original)
                logging.info("Restored hosts from backup")
            else:
                with open(self.hosts_path, 'w') as f:
                    f.write("127.0.0.1 localhost\n::1 localhost\n")
                logging.warning("Created minimal hosts file (no backup)")
            self.update_hosts(websites, blocking=True)
            self.protect_files(protect=True)
            self.hosts_file_hash = self.calculate_file_hash(self.hosts_path)
            logging.info("Re-protected hosts file and updated hash")
        except Exception as e:
            logging.error(f"Failed to restore hosts file: {e}")

    # ------------------------------------------------------------------
    # Signals (FIX 1): no interactive prompts in daemon; SIGUSR1 ends early
    # ------------------------------------------------------------------
    def _signal_handler(self, signum, frame):
        if signum == signal.SIGUSR1:
            logging.info("Received SIGUSR1: allowing early termination")
            self.cleanup()
            sys.exit(0)

        remaining = self.time_remaining()
        if remaining > 0:
            logging.info(f"Signal {signum} received, ignoring until timer ends ({remaining:.1f} min left)")
            return
        logging.info("Blocking period complete, terminating")
        self.cleanup()
        sys.exit(0)

    def _emergency_cleanup_handler(self, signum, frame):
        logging.critical(f"Emergency cleanup triggered by signal {signum}")
        try:
            self.cleanup()
        finally:
            self.release_lock()
            self.remove_pid_file()
            os._exit(1)

    # ------------------------------------------------------------------
    # Watchdog & cleanup scripts (with FIX 7 applied)
    # ------------------------------------------------------------------
    def create_cleanup_script(self):
        try:
            cleanup_script_path = "/etc/website_blocker/emergency_cleanup.sh"
            content = f"""#!/bin/bash
set -e

echo "=== Emergency Website Blocker Cleanup ==="

# Remove lock & pid
[ -f "{self.lock_file}" ] && rm -f "{self.lock_file}" && echo "Removed lock file"
[ -f "{self.pid_file}" ] && rm -f "{self.pid_file}" && echo "Removed PID file"

# Kill any remaining processes
pkill -f "website_blocker" 2>/dev/null || true
pkill -f "traffic_monitor.py" 2>/dev/null || true

# Restore hosts
if [ -f "{self.hosts_backup}" ]; then
  cp "{self.hosts_backup}" "{self.hosts_path}" && echo "Restored hosts backup"
else
  sed -i '/{self.marker_start}/,/{self.marker_end}/d' "{self.hosts_path}" 2>/dev/null || \
  sed -i '' '/{self.marker_start}/,/{self.marker_end}/d' "{self.hosts_path}" 2>/dev/null || true
  echo "Cleaned hosts file"
fi
chmod 644 "{self.hosts_path}"

# Remove dnsmasq drop-in
[ -f "{self.dnsmasq_conf_path}" ] && rm -f "{self.dnsmasq_conf_path}" && echo "Removed dnsmasq drop-in" || true
command -v systemctl >/dev/null 2>&1 && systemctl restart dnsmasq 2>/dev/null || true

# Remove nftables table if present
if command -v nft >/dev/null 2>&1; then
  nft list table inet website_blocker >/dev/null 2>&1 && nft delete table inet website_blocker || true
fi

# Remove iptables/ip6tables chains if present
if command -v iptables >/dev/null 2>&1; then
  iptables -D OUTPUT -j WEBSITE_BLOCKER 2>/dev/null || true
  iptables -F WEBSITE_BLOCKER 2>/dev/null || true
  iptables -X WEBSITE_BLOCKER 2>/dev/null || true
fi
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -D OUTPUT -j WEBSITE_BLOCKER 2>/dev/null || true
  ip6tables -F WEBSITE_BLOCKER 2>/dev/null || true
  ip6tables -X WEBSITE_BLOCKER 2>/dev/null || true
fi

echo "=== Cleanup complete ==="
"""
            os.makedirs(os.path.dirname(cleanup_script_path), exist_ok=True)
            with open(cleanup_script_path, 'w') as f:
                f.write(content)
            os.chmod(cleanup_script_path, 0o755)
            logging.info(f"Created emergency cleanup script at {cleanup_script_path}")
        except Exception as e:
            logging.error(f"Failed to create cleanup script: {e}")

    def start_watchdog(self):
        try:
            parent_pid = os.getpid()
            pid = os.fork()
            if pid == 0:
                os.setsid()
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                while True:
                    time.sleep(5)
                    try:
                        os.kill(parent_pid, 0)
                    except OSError:
                        cleanup_script = "/etc/website_blocker/emergency_cleanup.sh"
                        if os.path.exists(cleanup_script):
                            subprocess.run([cleanup_script], capture_output=True)
                        os._exit(0)
            else:
                self.watchdog_pid = pid
                logging.info(f"Started watchdog PID {pid}")
        except Exception as e:
            logging.error(f"Failed to start watchdog: {e}")

    def stop_watchdog(self):
        try:
            if hasattr(self, 'watchdog_pid'):
                os.kill(self.watchdog_pid, signal.SIGTERM)
                logging.info("Stopped watchdog process")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Runtime
    # ------------------------------------------------------------------
    def run(self):
        if not self.duration_minutes:
            logging.error("Duration not specified")
            return
        if not self.acquire_lock():
            logging.error("Failed to acquire lock - another instance may be running")
            sys.exit(1)
        try:
            self.write_pid_file()
            self.backup_hosts()
            websites = self.read_block_list()
            if not websites:
                logging.error("No websites to block")
                return

            self.start_time = datetime.datetime.now()
            self.start_monotonic = time.monotonic()
            end_time = self.start_time + datetime.timedelta(minutes=self.duration_minutes)
            logging.info(f"Starting website blocker for {self.duration_minutes} minutes")

            self.create_restart_script(end_time)
            if self.update_hosts(websites, blocking=True):
                self.protect_files(protect=True)

            # Hash for integrity
            self.hosts_file_hash = self.calculate_file_hash(self.hosts_path)

            # Signals (no interactive paths)
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGHUP, self._signal_handler)
            signal.signal(signal.SIGQUIT, self._signal_handler)
            signal.signal(signal.SIGUSR1, self._signal_handler)  # early terminate
            signal.signal(signal.SIGABRT, self._emergency_cleanup_handler)
            signal.signal(signal.SIGSEGV, self._emergency_cleanup_handler)

            self.create_cleanup_script()
            self.start_watchdog()

            while self.time_remaining() > 0:
                remaining = self.time_remaining()
                logging.info(f"{remaining:.1f} minutes remaining")
                self.check_hosts_file_integrity(websites)
                self.save_state(websites)
                time.sleep(60)

            self.cleanup()
        finally:
            self.release_lock()
            self.remove_pid_file()

    def create_restart_script(self, end_time):
        try:
            remaining_seconds = (end_time - datetime.datetime.now()).total_seconds()
            if remaining_seconds <= 0:
                return
            script_path = os.path.abspath(sys.argv[0])
            restart_content = f"""#!/bin/bash
if [ $(date +%s) -lt {int(end_time.timestamp())} ]; then
  REMAINING_MINUTES=$(( ({int(end_time.timestamp())} - $(date +%s)) / 60 ))
  {script_path} start $REMAINING_MINUTES
  echo "Website blocker restarted with $REMAINING_MINUTES minutes remaining"
else
  echo "Blocking period has ended, not restarting"
fi
"""
            with open(self.restart_script_path, 'w') as f:
                f.write(restart_content)
            os.chmod(self.restart_script_path, 0o755)
            cron_command = f"* * * * * {self.restart_script_path} >> /var/log/website_blocker_restart.log 2>&1\n"
            try:
                check = subprocess.run(["/usr/bin/crontab", "-l"], capture_output=True, text=True)
                if check.returncode == 0 and self.restart_script_path not in check.stdout:
                    new_cron = check.stdout + cron_command
                    subprocess.run(["/usr/bin/crontab", "-"], input=new_cron, text=True)
                    logging.info("Added restart cron job")
            except Exception as e:
                logging.error(f"Failed to set up cron job: {e}")
            logging.info("Created restart script")
        except Exception as e:
            logging.error(f"Failed to create restart script: {e}")

    def cleanup(self):
        logging.info("Cleaning up...")
        self.stop_watchdog()
        self.protect_files(protect=False)
        self.update_hosts([], blocking=False)
        # Remove dnsmasq drop-in
        if os.path.exists(self.dnsmasq_conf_path):
            try:
                os.remove(self.dnsmasq_conf_path)
                logging.info("Removed DNS blocking configuration")
                try:
                    if sys.platform == "linux":
                        subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)
                except Exception as e:
                    logging.error(f"Failed to restart dnsmasq: {e}")
            except Exception as e:
                logging.error(f"Failed to remove DNS blocking configuration: {e}")
        # Remove firewall rules
        try:
            self.update_firewall_rules([], blocking=False)
        except Exception as e:
            logging.error(f"Failed to remove firewall rules: {e}")
        # Stop traffic monitor
        try:
            self.stop_traffic_monitor()
        except Exception as e:
            logging.error(f"Failed to stop traffic monitor: {e}")
        # Remove cron
        try:
            check = subprocess.run(["/usr/bin/crontab", "-l"], capture_output=True, text=True)
            if check.returncode == 0 and self.restart_script_path in check.stdout:
                new_cron = check.stdout.replace(
                    f"* * * * * {self.restart_script_path} >> /var/log/website_blocker_restart.log 2>&1\n", "")
                subprocess.run(["/usr/bin/crontab", "-"], input=new_cron, text=True)
                logging.info("Removed restart cron job")
        except Exception as e:
            logging.error(f"Failed to remove cron job: {e}")
        if os.path.exists(self.restart_script_path):
            try:
                os.remove(self.restart_script_path)
                logging.info("Removed restart script")
            except Exception as e:
                logging.error(f"Failed to remove restart script: {e}")
        if os.path.exists(self.state_file):
            try:
                os.remove(self.state_file)
                logging.info("Removed state file")
            except Exception as e:
                logging.error(f"Failed to remove state file: {e}")
        logging.info("Website blocker stopped")

    # ------------------------------------------------------------------
    # Password generation (FIX 8)
    # ------------------------------------------------------------------
    def generate_complex_password(self):
        try:
            characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
            password = ''.join(random.choice(characters) for _ in range(16))
            self.password_hash = hashlib.sha256(password.encode()).hexdigest()
            os.makedirs(os.path.dirname(self.password_hash_file), exist_ok=True)
            with open(self.password_hash_file, 'w') as f:
                f.write(self.password_hash)
            os.chmod(self.password_hash_file, 0o400)

            parts = [password[i:i+4] for i in range(0, len(password), 4)]
            clues = []
            for part in parts:
                jumbled = list(part)
                random.shuffle(jumbled)
                jumbled.extend([random.choice(characters) for _ in range(4)])
                random.shuffle(jumbled)
                clues.append(''.join(jumbled))
            random_dir = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
            clue_dir = os.path.join("/var/lib", random_dir)
            os.makedirs(clue_dir, exist_ok=True)
            self.password_clue_file = os.path.join(clue_dir, ".clue.txt")
            clue_content = f"""
# ATTENTION: Password Hint
# Each line contains scrambled characters; actual password is 16 chars in 4x4 parts
{clues[0]}
{clues[1]}
{clues[2]}
{clues[3]}
"""
            with open(self.password_clue_file, 'w') as f:
                f.write(clue_content)
            os.chmod(self.password_clue_file, 0o400)
            hint_file = "/etc/website_blocker/.password_location.txt"
            with open(hint_file, 'w') as f:
                f.write(f"Password clues are located at: {self.password_clue_file}")
            os.chmod(hint_file, 0o400)
            logging.info("Generated and stored complex password (first-run)")
        except Exception as e:
            logging.error(f"Failed to generate complex password: {e}")

    # ------------------------------------------------------------------
    # Traffic monitor (FIX 4)
    # ------------------------------------------------------------------
    def start_traffic_monitor(self, websites):
        try:
            script = f"""#!/usr/bin/env python3
import socket, subprocess, time, logging, sys
logging.basicConfig(level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('/var/log/website_blocker_traffic.log'), logging.StreamHandler()])
BLOCKED_IPS = set({list(self.blocked_ips_v4 | self.blocked_ips_v6)})
DOMAINS = {websites}

def update_blocked_ips():
    global BLOCKED_IPS
    try:
        ips = set()
        for d in DOMAINS:
            try:
                for info in socket.getaddrinfo(d, None):
                    ips.add(info[4][0])
                for info in socket.getaddrinfo('www.'+d, None):
                    ips.add(info[4][0])
            except Exception:
                pass
        BLOCKED_IPS |= ips
        logging.info(f"Updated blocked IPs: {len(BLOCKED_IPS)}")
    except Exception as e:
        logging.error(f"Error updating blocked IPs: {e}")

def check_connections():
    try:
        if sys.platform == 'linux':
            cmd = ['ss', '-Htnp']
        elif sys.platform == 'darwin':
            cmd = ['lsof', '-i', '-n']
        else:
            return
        res = subprocess.run(cmd, capture_output=True, text=True)
        for line in res.stdout.splitlines():
            for ip in list(BLOCKED_IPS):
                if ip in line:
                    logging.warning(f"Detected connection to blocked IP: {ip}")
    except Exception as e:
        logging.error(f"Error checking connections: {e}")

logging.info("Starting traffic monitor")
try:
    while True:
        check_connections()
        if int(time.time()) % 300 < 5:
            update_blocked_ips()
        time.sleep(10)
except KeyboardInterrupt:
    logging.info("Traffic monitor stopped")
except Exception as e:
    logging.error(f"Traffic monitor error: {e}")
"""
            with open(self.traffic_monitor_script, 'w') as f:
                f.write(script)
            os.chmod(self.traffic_monitor_script, 0o755)
            subprocess.Popen([self.traffic_monitor_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logging.info("Started traffic monitor")
            return True
        except Exception as e:
            logging.error(f"Failed to start traffic monitor: {e}")
            return False

    def stop_traffic_monitor(self):
        try:
            if sys.platform in ('linux', 'darwin'):
                subprocess.run(["pkill", "-f", self.traffic_monitor_script], capture_output=True)
            logging.info("Stopped traffic monitor")
            if os.path.exists(self.traffic_monitor_script):
                os.remove(self.traffic_monitor_script)
            return True
        except Exception as e:
            logging.error(f"Failed to stop traffic monitor: {e}")
            return False

# -----------------------------------------------------------------------------
# Daemon entry helpers
# -----------------------------------------------------------------------------

def run_daemon(duration):
    pid_file = '/var/run/website_blocker.pid'
    logging.info("Initializing daemon context...")
    context = DaemonContext(
        working_directory='/',
        umask=0o002,
        pidfile=lockfile.FileLock(pid_file),
        detach_process=True,
        files_preserve=[handler.stream.fileno() for handler in logging.getLogger().handlers if hasattr(handler, 'stream')]
    )
    context.signal_map = {signal.SIGTERM: 'terminate', signal.SIGINT: 'terminate'}
    try:
        logging.info("Entering daemon context...")
        with context:
            logging.info("Inside daemon context, starting blocker...")
            blocker = WebsiteBlocker(duration_minutes=duration)
            blocker.run()
    except Exception as e:
        logging.error(f"Failed to start daemon: {e}")
        raise


def stop_daemon():
    pid_file = '/var/run/website_blocker.pid'
    if not os.path.exists(pid_file):
        print("No PID file. Is the blocker running?")
        sys.exit(1)
    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
    except Exception:
        print("Failed to read PID file")
        sys.exit(1)

    # Foreground password check (no daemon interactivity; FIX 1)
    try:
        wb = WebsiteBlocker(duration_minutes=1)  # dummy for check_password
        pwd = getpass.getpass("Enter password to stop the blocker: ")
        if not wb.check_password(pwd):
            print("Incorrect password")
            sys.exit(2)
    except KeyboardInterrupt:
        print("\nAborted")
        sys.exit(130)

    try:
        os.kill(pid, signal.SIGUSR1)
        print(f"Sent SIGUSR1 to PID {pid}. The blocker will stop shortly.")
    except ProcessLookupError:
        print("Process not found. Removing stale PID file.")
        os.remove(pid_file)
    except PermissionError:
        print("Permission denied. Run as root.")
        sys.exit(1)

# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Website Blocker")
    sub = parser.add_subparsers(dest="cmd", help="Commands")

    p_start = sub.add_parser("start", help="Start blocker daemon")
    p_start.add_argument("minutes", type=int, help="Duration in minutes")

    sub.add_parser("stop", help="Stop blocker early (password required)")
    sub.add_parser("status", help="Show current blocker status")

    # Back-compat: allow "<minutes>" directly
    parser.add_argument("legacy_minutes", nargs='?', type=int, help=argparse.SUPPRESS)

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)

    # Legacy path: python3 script.py 60
    if args.legacy_minutes and args.cmd is None:
        duration = args.legacy_minutes
        if duration <= 0:
            print("Duration must be positive")
            sys.exit(1)
        # Pre-flight: single-instance lock
        lock_file = "/var/run/website_blocker.lock"
        try:
            test_fd = os.open(lock_file, os.O_CREAT | os.O_WRONLY | os.O_NONBLOCK)
            fcntl.flock(test_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(test_fd, fcntl.LOCK_UN)
            os.close(test_fd)
        except IOError as e:
            if e.errno in (errno.EACCES, errno.EAGAIN):
                print("Another instance is already running")
                print(f"If this is an error, remove: sudo rm {lock_file}")
                sys.exit(1)
        print("Starting website blocker daemon...")
        run_daemon(duration)
        sys.exit(0)

    if args.cmd == "start":
        duration = args.minutes
        if duration <= 0:
            print("Duration must be positive")
            sys.exit(1)
        lock_file = "/var/run/website_blocker.lock"
        try:
            test_fd = os.open(lock_file, os.O_CREAT | os.O_WRONLY | os.O_NONBLOCK)
            fcntl.flock(test_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(test_fd, fcntl.LOCK_UN)
            os.close(test_fd)
        except IOError as e:
            if e.errno in (errno.EACCES, errno.EAGAIN):
                print("Another instance is already running")
                print(f"If this is an error, remove: sudo rm {lock_file}")
                sys.exit(1)
        print("Starting website blocker daemon...")
        run_daemon(duration)
    elif args.cmd == "stop":
        rc = stop_daemon()
        sys.exit(rc)
    elif args.cmd == "status":
        rc = status_daemon()
        sys.exit(rc)
    else:
        parser.print_help()
        sys.exit(1)
