#!/usr/bin/env python3
import os
import sys
import time
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
from daemon.daemon import DaemonContext
import lockfile

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/website_blocker.log'),
        logging.StreamHandler()
    ]
)

class WebsiteBlocker:
    def __init__(self, duration_minutes=None):
        # Use an absolute path in /etc for the block list
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
        self.dnsmasq_conf_path = "/etc/dnsmasq.conf.d/website_blocker.conf"
        self.iptables_rules_file = "/etc/website_blocker/iptables_rules.sh"
        self.traffic_monitor_script = "/etc/website_blocker/traffic_monitor.py"
        self.blocked_ips = set()  # Set to store resolved IPs of blocked websites
        self.state_file = "/etc/website_blocker/blocker_state.json"
        
        # Auto-generate a password
        self.generate_complex_password()
        
        # Ensure block list directory exists
        block_list_dir = os.path.dirname(self.block_list_path)
        if not os.path.exists(block_list_dir):
            try:
                os.makedirs(block_list_dir, exist_ok=True)
                logging.info(f"Created block list directory: {block_list_dir}")
            except Exception as e:
                logging.error(f"Failed to create block list directory: {e}")
                sys.exit(1)
    
    def acquire_lock(self):
        """Acquire an exclusive lock to prevent multiple instances"""
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.lock_file), exist_ok=True)
            
            # Open the lock file
            self.lock_fd = os.open(self.lock_file, os.O_CREAT | os.O_WRONLY)
            
            # Try to acquire an exclusive lock
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            
            # Write our PID to the file
            os.write(self.lock_fd, str(os.getpid()).encode())
            os.fsync(self.lock_fd)
            
            logging.info(f"Acquired exclusive lock with PID {os.getpid()}")
            return True
            
        except IOError as e:
            if e.errno in (errno.EACCES, errno.EAGAIN):
                # Another instance is running
                try:
                    with open(self.lock_file, 'r') as f:
                        other_pid = f.read().strip()
                    logging.error(f"Another instance is already running with PID {other_pid}")
                except:
                    logging.error("Another instance is already running")
                return False
            else:
                logging.error(f"Failed to acquire lock: {e}")
                return False
        except Exception as e:
            logging.error(f"Unexpected error acquiring lock: {e}")
            return False
    
    def release_lock(self):
        """Release the exclusive lock"""
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
        """Write the current PID to the PID file"""
        try:
            with open(self.pid_file, 'w') as f:
                f.write(str(os.getpid()))
            logging.info(f"Written PID {os.getpid()} to {self.pid_file}")
        except Exception as e:
            logging.error(f"Failed to write PID file: {e}")
    
    def remove_pid_file(self):
        """Remove the PID file"""
        try:
            if os.path.exists(self.pid_file):
                os.remove(self.pid_file)
                logging.info("Removed PID file")
        except Exception as e:
            logging.error(f"Failed to remove PID file: {e}")
    
    def create_cleanup_script(self):
        """Create an emergency cleanup script that can be run manually if the blocker crashes"""
        try:
            cleanup_script_path = "/etc/website_blocker/emergency_cleanup.sh"
            cleanup_content = f"""#!/bin/bash
# Emergency cleanup script for website blocker
# Run this if the blocker crashes and leaves the system in a blocked state

echo "=== Emergency Website Blocker Cleanup ==="

# Remove the lock file
if [ -f "{self.lock_file}" ]; then
    rm -f "{self.lock_file}"
    echo "Removed lock file"
fi

# Remove the PID file
if [ -f "{self.pid_file}" ]; then
    rm -f "{self.pid_file}"
    echo "Removed PID file"
fi

# Kill any remaining blocker processes
pkill -f "blocker.py" 2>/dev/null
pkill -f "website_blocker" 2>/dev/null

# Restore hosts file from backup
if [ -f "{self.hosts_backup}" ]; then
    cp "{self.hosts_backup}" "{self.hosts_path}"
    echo "Restored hosts file from backup"
else
    # If no backup, remove blocker entries manually
    sed -i '/{self.marker_start}/,/{self.marker_end}/d' "{self.hosts_path}" 2>/dev/null || \
    sed -i '' '/{self.marker_start}/,/{self.marker_end}/d' "{self.hosts_path}" 2>/dev/null
    echo "Cleaned hosts file"
fi

# Make hosts file writable again
chmod 644 "{self.hosts_path}"

# Remove DNS blocking if configured
if [ -f "{self.dnsmasq_conf_path}" ]; then
    rm -f "{self.dnsmasq_conf_path}"
    echo "Removed DNS blocking configuration"
    
    # Restart dnsmasq if available
    if command -v systemctl &> /dev/null; then
        systemctl restart dnsmasq 2>/dev/null
    fi
fi

# Remove firewall rules
if [ -f "{self.iptables_rules_file}" ]; then
    # Restore iptables rules
    iptables-restore < /etc/iptables/rules.v4.backup 2>/dev/null
    rm -f "{self.iptables_rules_file}"
    echo "Removed firewall rules"
fi

# Stop traffic monitor
pkill -f "{self.traffic_monitor_script}" 2>/dev/null
if [ -f "{self.traffic_monitor_script}" ]; then
    rm -f "{self.traffic_monitor_script}"
    echo "Stopped traffic monitor"
fi

# Flush DNS cache
if [[ "$OSTYPE" == "darwin"* ]]; then
    dscacheutil -flushcache 2>/dev/null
    killall -HUP mDNSResponder 2>/dev/null
else
    systemctl restart systemd-resolved 2>/dev/null || \
    service nscd restart 2>/dev/null || \
    service dnsmasq restart 2>/dev/null
fi

echo "=== Cleanup complete ==="
echo "Your system should now be restored to normal operation."
echo "If you still have issues, try rebooting your system."
"""
            
            os.makedirs(os.path.dirname(cleanup_script_path), exist_ok=True)
            with open(cleanup_script_path, 'w') as f:
                f.write(cleanup_content)
            os.chmod(cleanup_script_path, 0o755)
            
            logging.info(f"Created emergency cleanup script at {cleanup_script_path}")
            
        except Exception as e:
            logging.error(f"Failed to create cleanup script: {e}")
    
    def start_watchdog(self):
        """Start a watchdog process that monitors the main blocker and cleans up if it crashes"""
        try:
            parent_pid = os.getpid()
            
            # Fork a child process for the watchdog
            pid = os.fork()
            
            if pid == 0:  # Child process (watchdog)
                # Detach from parent process group
                os.setsid()
                
                # Ignore signals that might affect the parent
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                
                logging.info(f"Watchdog started for parent PID {parent_pid}")
                
                while True:
                    time.sleep(5)  # Check every 5 seconds
                    
                    # Check if parent process is still alive
                    try:
                        os.kill(parent_pid, 0)  # Signal 0 just checks if process exists
                    except OSError:
                        # Parent process is dead, perform cleanup
                        logging.critical(f"Parent process {parent_pid} has died! Performing emergency cleanup...")
                        
                        # Run the emergency cleanup script
                        cleanup_script = "/etc/website_blocker/emergency_cleanup.sh"
                        if os.path.exists(cleanup_script):
                            subprocess.run([cleanup_script], capture_output=True)
                        
                        # Exit the watchdog
                        os._exit(0)
            
            else:  # Parent process
                self.watchdog_pid = pid
                logging.info(f"Started watchdog process with PID {pid}")
                
        except Exception as e:
            logging.error(f"Failed to start watchdog: {e}")
    
    def stop_watchdog(self):
        """Stop the watchdog process"""
        try:
            if hasattr(self, 'watchdog_pid'):
                os.kill(self.watchdog_pid, signal.SIGTERM)
                logging.info("Stopped watchdog process")
        except:
            pass
    
    def save_state(self, websites):
        """Save the current state to a file for recovery"""
        try:
            state = {
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'duration_minutes': self.duration_minutes,
                'websites': list(websites),
                'pid': os.getpid(),
                'hosts_hash': self.hosts_file_hash
            }
            
            with open(self.state_file, 'w') as f:
                import json
                json.dump(state, f)
                
        except Exception as e:
            logging.error(f"Failed to save state: {e}")
    
    def restore_state(self):
        """Restore state from file if it exists"""
        try:
            if not os.path.exists(self.state_file):
                return None
                
            with open(self.state_file, 'r') as f:
                import json
                state = json.load(f)
                
            # Check if the saved process is still running
            try:
                os.kill(state['pid'], 0)
                # Process is still running
                return None
            except OSError:
                # Process is not running, we can restore
                logging.info("Found orphaned state file, restoring...")
                return state
                
        except Exception as e:
            logging.error(f"Failed to restore state: {e}")
            return None
        
    def backup_hosts(self):
        """Create a backup of the hosts file if it doesn't exist"""
        if not os.path.exists(self.hosts_backup):
            try:
                with open(self.hosts_path, 'r') as src, open(self.hosts_backup, 'w') as dst:
                    dst.write(src.read())
                logging.info("Created hosts file backup")
            except Exception as e:
                logging.error(f"Failed to create hosts backup: {e}")
                sys.exit(1)

    def read_block_list(self):
        """Read the list of websites to block"""
        # Create a default block list if it doesn't exist
        if not os.path.exists(self.block_list_path):
            self.create_default_block_list()
            
        try:
            with open(self.block_list_path, 'r') as f:
                logging.info(f"Reading block list from {self.block_list_path}")
                blocked_websites = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logging.info(f"Found {len(blocked_websites)} websites to block")
                return blocked_websites
        except Exception as e:
            logging.error(f"Failed to read block list: {e}")
            return []
    
    def create_default_block_list(self):
        """Create a default block list with common distracting websites"""
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
        

    def send_ping_to_blocked_websites(self):
        """Send a ping to each blocked website and expect a response containing the word '127.0.0.1'"""
        for website in self.read_block_list():
            result = subprocess.run(["ping", "-c", "1", website], capture_output=True, text=True)
            logging.info(f"Ping to {website} returned: {result.stdout}")
            if "127.0.0.1" not in result.stdout:
                logging.error(f"Ping to {website} did not return '127.0.0.1'")
                return False
        return True

    def flush_dns_cache(self):
        """Flush DNS cache to apply changes immediately"""
        try:
            if sys.platform == "darwin":  # macOS
                os.system("dscacheutil -flushcache")
                os.system("killall -HUP mDNSResponder")
                logging.info("Flushed DNS cache (macOS)")
            elif sys.platform == "linux":  # Linux
                os.system("systemd-resolve --flush-caches")  # For systemd-based systems
                logging.info("Flushed DNS cache (Linux)")
            # Add Windows support if needed
            return True
        except Exception as e:
            logging.error(f"Failed to flush DNS cache: {e}")
            return False

    def update_hosts(self, websites, blocking=True):
        """Update the hosts file with the blocked/unblocked websites"""
        try:
            # Read current hosts content
            with open(self.hosts_path, 'r') as f:
                hosts_content = f.read()

            # Remove any existing block section
            if self.marker_start in hosts_content:
                start_idx = hosts_content.index(self.marker_start)
                end_idx = hosts_content.index(self.marker_end) + len(self.marker_end)
                hosts_content = hosts_content[:start_idx] + hosts_content[end_idx:]

            if blocking:
                # Clear the blocked IPs set
                self.blocked_ips.clear()
                
                # Create new block section
                block_section = [self.marker_start]
                for website in websites:
                    block_section.append(f"127.0.0.1 {website}")
                    block_section.append(f"127.0.0.1 www.{website}")
                    
                    # Resolve website to IP addresses for network monitoring
                    try:
                        ips = socket.gethostbyname_ex(website)[2]
                        self.blocked_ips.update(ips)
                        
                        # Also try with www prefix
                        try:
                            www_ips = socket.gethostbyname_ex(f"www.{website}")[2]
                            self.blocked_ips.update(www_ips)
                        except:
                            pass
                    except:
                        logging.warning(f"Could not resolve IP for {website}")
                        
                block_section.append(self.marker_end)

                # Write updated hosts file
                with open(self.hosts_path, 'w') as f:
                    f.write(hosts_content.strip() + '\n\n' + '\n'.join(block_section))
                
                # Also apply DNS-level blocking as a redundant measure
                self.update_dns_blocking(websites, blocking=True)
                
                # Add firewall rules as a third layer of protection
                self.update_firewall_rules(websites, blocking=True)
                
                # Start the traffic monitor to detect direct IP access
                self.start_traffic_monitor(websites)
            else:
                # Just write the original content without blocks
                with open(self.hosts_path, 'w') as f:
                    f.write(hosts_content.strip() + '\n')
                
                # Remove DNS blocking too
                self.update_dns_blocking(websites, blocking=False)
                
                # Remove firewall rules
                self.update_firewall_rules(websites, blocking=False)
                
                # Stop the traffic monitor
                self.stop_traffic_monitor()

            # Flush DNS cache after updating hosts file
            self.flush_dns_cache()
            self.send_ping_to_blocked_websites()
            
            logging.info("Updated hosts file - blocking: %s", blocking)
            return True
        except Exception as e:
            logging.error(f"Failed to update hosts file: {e}")
            return False
            
    def update_dns_blocking(self, websites, blocking=True):
        """Implement DNS-level blocking as a redundant measure"""
        try:
            # Check if dnsmasq is installed
            if subprocess.run(["which", "dnsmasq"], capture_output=True).returncode != 0:
                logging.warning("dnsmasq not found, skipping DNS-level blocking")
                return False
                
            # Ensure dnsmasq.conf.d directory exists
            conf_dir = os.path.dirname(self.dnsmasq_conf_path)
            os.makedirs(conf_dir, exist_ok=True)
            
            if blocking and websites:
                # Create dnsmasq configuration to redirect blocked websites to localhost
                with open(self.dnsmasq_conf_path, 'w') as f:
                    f.write("# Website Blocker DNS Configuration\n")
                    for website in websites:
                        f.write(f"address=/{website}/127.0.0.1\n")
                        f.write(f"address=/www.{website}/127.0.0.1\n")
                logging.info("Created DNS blocking configuration")
                
                # Restart dnsmasq service if it's active
                try:
                    if sys.platform == "linux":
                        subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)
                    else:
                        # For macOS, different approaches would be needed
                        pass
                except Exception as e:
                    logging.error(f"Failed to restart dnsmasq: {e}")
            else:
                # Remove the configuration file if it exists
                if os.path.exists(self.dnsmasq_conf_path):
                    os.remove(self.dnsmasq_conf_path)
                    logging.info("Removed DNS blocking configuration")
                    
                    # Restart dnsmasq service if it's active
                    try:
                        if sys.platform == "linux":
                            subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)
                        else:
                            # For macOS, different approaches would be needed
                            pass
                    except Exception as e:
                        logging.error(f"Failed to restart dnsmasq: {e}")
            
            return True
        except Exception as e:
            logging.error(f"Failed to update DNS blocking: {e}")
            return False

    def update_firewall_rules(self, websites, blocking=True):
        """Add or remove firewall rules to block websites at the network level"""
        try:
            # Check which firewall tool is available
            if self._is_command_available("iptables"):
                return self._update_iptables_rules(websites, blocking)
            elif self._is_command_available("pf") and sys.platform == "darwin":
                return self._update_pf_rules(websites, blocking)
            else:
                logging.warning("No supported firewall tools found, skipping firewall-level blocking")
                return False
        except Exception as e:
            logging.error(f"Failed to update firewall rules: {e}")
            return False
            
    def _is_command_available(self, command):
        """Check if a command is available on the system"""
        return subprocess.run(["which", command], capture_output=True).returncode == 0
        
    def _update_iptables_rules(self, websites, blocking=True):
        """Add or remove iptables rules for Linux systems"""
        try:
            if blocking and websites:
                # Create a script to apply the rules
                script_content = "#!/bin/bash\n\n"
                script_content += "# Clear any existing website blocker rules\n"
                script_content += "iptables -F WEBSITE_BLOCKER 2>/dev/null || iptables -N WEBSITE_BLOCKER\n"
                script_content += "iptables -D OUTPUT -j WEBSITE_BLOCKER 2>/dev/null\n"
                script_content += "iptables -F WEBSITE_BLOCKER\n\n"
                
                # Add rules for each blocked website
                script_content += "# Add rules for blocked websites\n"
                for website in websites:
                    # Try to resolve the domain to IP addresses
                    try:
                        ips = socket.gethostbyname_ex(website)[2]
                        for ip in ips:
                            script_content += f"iptables -A WEBSITE_BLOCKER -d {ip} -j REJECT\n"
                        
                        # Also try with www prefix
                        try:
                            www_ips = socket.gethostbyname_ex(f"www.{website}")[2]
                            for ip in www_ips:
                                if ip not in ips:  # Avoid duplicates
                                    script_content += f"iptables -A WEBSITE_BLOCKER -d {ip} -j REJECT\n"
                        except:
                            pass
                    except:
                        logging.warning(f"Could not resolve IP for {website}, using domain blocking only")
                
                script_content += "\n# Enable the WEBSITE_BLOCKER chain\n"
                script_content += "iptables -A OUTPUT -j WEBSITE_BLOCKER\n"
                
                # Save the script
                with open(self.iptables_rules_file, 'w') as f:
                    f.write(script_content)
                
                # Make it executable
                os.chmod(self.iptables_rules_file, 0o755)
                
                # Execute the script
                subprocess.run([self.iptables_rules_file], capture_output=True)
                logging.info("Applied iptables firewall rules")
                
            else:
                # Remove the rules if they exist
                if os.path.exists(self.iptables_rules_file):
                    # Create a cleanup script
                    with open(self.iptables_rules_file, 'w') as f:
                        f.write("#!/bin/bash\n\n")
                        f.write("# Remove website blocker rules\n")
                        f.write("iptables -D OUTPUT -j WEBSITE_BLOCKER 2>/dev/null\n")
                        f.write("iptables -F WEBSITE_BLOCKER 2>/dev/null\n")
                        f.write("iptables -X WEBSITE_BLOCKER 2>/dev/null\n")
                    
                    # Make it executable
                    os.chmod(self.iptables_rules_file, 0o755)
                    
                    # Execute the script
                    subprocess.run([self.iptables_rules_file], capture_output=True)
                    logging.info("Removed iptables firewall rules")
            
            return True
        except Exception as e:
            logging.error(f"Failed to update iptables rules: {e}")
            return False
            
    def _update_pf_rules(self, websites, blocking=True):
        """Add or remove pf rules for macOS systems"""
        try:
            if blocking and websites:
                # For macOS, we would create a pfctl configuration
                # This is a simplified version - for real use, more extensive testing on macOS would be needed
                pf_rules = "# Website Blocker PF Rules\n"
                for website in websites:
                    pf_rules += f"block out proto tcp to {website}\n"
                    pf_rules += f"block out proto tcp to www.{website}\n"
                
                # Create a temporary file for the rules
                with open("/tmp/website_blocker_pf.conf", 'w') as f:
                    f.write(pf_rules)
                
                # Load the rules
                subprocess.run(["pfctl", "-f", "/tmp/website_blocker_pf.conf"], capture_output=True)
                logging.info("Applied pf firewall rules")
            else:
                # Remove the rules (simplified - would need to be more carefully implemented in production)
                if os.path.exists("/tmp/website_blocker_pf.conf"):
                    os.remove("/tmp/website_blocker_pf.conf")
                logging.info("Removed pf firewall rules")
            
            return True
        except Exception as e:
            logging.error(f"Failed to update pf rules: {e}")
            return False

    def protect_files(self, protect=True):
        """Make the block list and hosts file immutable/mutable"""
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

    def time_remaining(self):
        """Calculate remaining blocking time in minutes using monotonic clock"""
        if not hasattr(self, 'start_monotonic') or not self.duration_minutes:
            return 0
        elapsed = (time.monotonic() - self.start_monotonic) / 60
        remaining = self.duration_minutes - elapsed
        return max(0, remaining)

    def run(self):
        """Main daemon loop"""
        print("Running daemon loop")
        if not self.duration_minutes:
            logging.error("Duration not specified")
            return

        # Acquire exclusive lock to prevent multiple instances
        if not self.acquire_lock():
            logging.error("Failed to acquire lock - another instance may be running")
            sys.exit(1)
        
        try:
            # Write PID file after acquiring lock
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
            
            # Create a restart script that will be triggered if the process is killed forcefully
            self.create_restart_script(end_time)

            # Enable blocking
            if self.update_hosts(websites, blocking=True):
                self.protect_files(protect=True)
            
            # Calculate the expected hash of the hosts file for integrity checking
            self.hosts_file_hash = self.calculate_file_hash(self.hosts_path)
            logging.info("Calculated initial hosts file hash for integrity monitoring")
            
            # Set up comprehensive signal handlers
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGHUP, self._signal_handler)
            signal.signal(signal.SIGQUIT, self._signal_handler)
            
            # Set up signal handler for unexpected termination
            signal.signal(signal.SIGABRT, self._emergency_cleanup_handler)
            signal.signal(signal.SIGSEGV, self._emergency_cleanup_handler)
            
            # Create emergency cleanup script
            self.create_cleanup_script()
            
            # Create watchdog process
            self.start_watchdog()
            
            logging.info("Website blocker is now running in active mode")
            
            # Keep checking the time
            while self.time_remaining() > 0:
                remaining = self.time_remaining()
                logging.info(f"{remaining:.1f} minutes remaining")
                
                # Check hosts file integrity
                self.check_hosts_file_integrity(websites)
                
                # Save state periodically
                self.save_state(websites)
                
                time.sleep(60)  # Check every minute

            # Cleanup when time is up
            self.cleanup()
        
        finally:
            # Always release the lock and remove PID file
            self.release_lock()
            self.remove_pid_file()
            
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            if not os.path.exists(file_path):
                return None
                
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            return file_hash
        except Exception as e:
            logging.error(f"Failed to calculate file hash: {e}")
            return None
            
    def check_hosts_file_integrity(self, websites):
        """Check if hosts file exists and hasn't been tampered with"""
        try:
            # Check if hosts file exists
            if not os.path.exists(self.hosts_path):
                logging.warning("Hosts file has been deleted! Restoring from backup...")
                self.restore_hosts_file(websites)
                return
                
            # Check if hosts file has been modified
            current_hash = self.calculate_file_hash(self.hosts_path)
            if current_hash != self.hosts_file_hash:
                logging.warning("Hosts file has been modified! Restoring blocked websites...")
                self.restore_hosts_file(websites)
                
        except Exception as e:
            logging.error(f"Error checking hosts file integrity: {e}")
            
    def restore_hosts_file(self, websites):
        """Restore hosts file and re-apply website blocks"""
        try:
            # If backup exists, restore it first
            if os.path.exists(self.hosts_backup):
                with open(self.hosts_backup, 'r') as src:
                    original_content = src.read()
                    
                # Write the original content back to the hosts file
                with open(self.hosts_path, 'w') as f:
                    f.write(original_content)
                logging.info("Restored hosts file from backup")
            else:
                # Create a minimal hosts file if backup doesn't exist
                with open(self.hosts_path, 'w') as f:
                    f.write("127.0.0.1 localhost\n::1 localhost\n")
                logging.warning("Created minimal hosts file (backup not found)")
            
            # Re-apply website blocks
            self.update_hosts(websites, blocking=True)
            self.protect_files(protect=True)
            
            # Update the hash
            self.hosts_file_hash = self.calculate_file_hash(self.hosts_path)
            logging.info("Re-protected hosts file and updated hash")
            
        except Exception as e:
            logging.error(f"Failed to restore hosts file: {e}")

    def _emergency_cleanup_handler(self, signum, frame):
        """Emergency cleanup handler for unexpected termination"""
        logging.critical(f"Emergency cleanup triggered by signal {signum}")
        try:
            self.cleanup()
        except:
            pass
        finally:
            self.release_lock()
            self.remove_pid_file()
            os._exit(1)
    
    def _signal_handler(self, signum, frame):
        """Handle termination signals"""
        remaining = self.time_remaining()
        if remaining > 0:
            logging.info(f"Signal received, but ignoring. {remaining:.1f} minutes remaining")
            
            # Check if password exists and give user a chance to use it for early termination
            if os.path.exists(self.password_hash_file):
                logging.info("Password protection active. You can terminate early with the correct password.")
                print("\n=== EARLY TERMINATION ===")
                print(f"You still have {remaining:.1f} minutes remaining in your blocking session.")
                print("To terminate early, you'll need to:")
                print("1. Solve the math challenge")
                print("2. Find the password hint file at: /etc/website_blocker/.password_location.txt")
                print("3. Use that file to locate the actual password clues")
                print("4. Decode the password from the clues")
                print("5. Enter the correct password when prompted")
                print("\nThis process is intentionally difficult to prevent impulsive termination.")
                
                # First, require solving a math challenge
                if not self.solve_challenge():
                    logging.info("Math challenge failed, continuing blocking")
                    return
                
                try:
                    print("\nYou've solved the math challenge! Now for the password hunt:")
                    print("1. First, check the hint file: sudo cat /etc/website_blocker/.password_location.txt")
                    print("2. That file will tell you where to find the actual password clues")
                    print("3. The password is 16 characters, split into 4 parts of 4 characters each")
                    print("4. In each clue line, find which 4 characters from the 8 characters belong to the password")
                    pwd = getpass.getpass("\nEnter password to terminate early (or press Ctrl+C to cancel): ")
                    if self.check_password(pwd):
                        logging.info("Password correct, allowing early termination")
                        self.cleanup()
                        sys.exit(0)
                    else:
                        print("Incorrect password. The blocking will continue.")
                        logging.info("Incorrect password, continuing blocking")
                except:
                    logging.info("Password entry cancelled, continuing blocking")
        else:
            logging.info("Blocking period complete, allowing termination")
            self.cleanup()
            sys.exit(0)

    def check_password(self, password):
        """Check if the provided password matches the stored hash"""
        try:
            # Read saved hash
            with open(self.password_hash_file, 'r') as f:
                stored_hash = f.read().strip()
            
            # Compute hash of provided password
            input_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Compare hashes
            return input_hash == stored_hash
        except Exception as e:
            logging.error(f"Failed to check password: {e}")
            return False

    def create_restart_script(self, end_time):
        """Create a script that will restart the blocker if it's killed forcefully"""
        try:
            # Calculate remaining time in minutes
            remaining_seconds = (end_time - datetime.datetime.now()).total_seconds()
            if remaining_seconds <= 0:
                return
                
            # Get the path to the current script
            script_path = os.path.abspath(sys.argv[0])
            
            # Create a script that will restart the blocker with the remaining time
            restart_content = f"""#!/bin/bash
# This script restarts the website blocker if it's killed
# It will only restart if the blocking period hasn't ended yet

# Check if current time is before the end time
if [ $(date +%s) -lt {int(end_time.timestamp())} ]; then
    # Calculate remaining minutes
    REMAINING_MINUTES=$(( ({int(end_time.timestamp())} - $(date +%s)) / 60 ))
    
    # Restart the blocker with the remaining time
    {script_path} $REMAINING_MINUTES
    
    echo "Website blocker restarted with $REMAINING_MINUTES minutes remaining"
else
    echo "Blocking period has ended, not restarting"
fi
"""
            # Write the restart script
            with open(self.restart_script_path, 'w') as f:
                f.write(restart_content)
                
            # Make it executable
            os.chmod(self.restart_script_path, 0o755)
            
            # Create a cron job to run the script every minute
            cron_command = f"* * * * * {self.restart_script_path} >> /var/log/website_blocker_restart.log 2>&1\n"
            
            # Add cron job
            try:
                # Check if the cron job already exists
                check_cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
                if check_cron.returncode == 0 and self.restart_script_path not in check_cron.stdout:
                    # Add the new cron job
                    new_cron = check_cron.stdout + cron_command
                    subprocess.run(["crontab", "-"], input=new_cron, text=True)
                    logging.info("Added restart cron job")
            except Exception as e:
                logging.error(f"Failed to set up cron job: {e}")
                
            logging.info("Created restart script")
        except Exception as e:
            logging.error(f"Failed to create restart script: {e}")

    def cleanup(self):
        """Remove blocks and file protection"""
        logging.info("Cleaning up...")
        
        # Stop the watchdog process first
        self.stop_watchdog()
        
        self.protect_files(protect=False)
        self.update_hosts([], blocking=False)
        
        # Remove DNS blocking configuration
        if os.path.exists(self.dnsmasq_conf_path):
            try:
                os.remove(self.dnsmasq_conf_path)
                logging.info("Removed DNS blocking configuration")
                
                # Restart dnsmasq service if it's active
                try:
                    if sys.platform == "linux":
                        subprocess.run(["systemctl", "restart", "dnsmasq"], capture_output=True)
                    else:
                        # For macOS, different approaches would be needed
                        pass
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
        
        # Remove cron job if it exists
        try:
            check_cron = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            if check_cron.returncode == 0 and self.restart_script_path in check_cron.stdout:
                # Remove the cron job
                new_cron = check_cron.stdout.replace(f"* * * * * {self.restart_script_path} >> /var/log/website_blocker_restart.log 2>&1\n", "")
                subprocess.run(["crontab", "-"], input=new_cron, text=True)
                logging.info("Removed restart cron job")
        except Exception as e:
            logging.error(f"Failed to remove cron job: {e}")
            
        # Remove restart script if it exists
        if os.path.exists(self.restart_script_path):
            try:
                os.remove(self.restart_script_path)
                logging.info("Removed restart script")
            except Exception as e:
                logging.error(f"Failed to remove restart script: {e}")
        
        # Remove state file
        if os.path.exists(self.state_file):
            try:
                os.remove(self.state_file)
                logging.info("Removed state file")
            except Exception as e:
                logging.error(f"Failed to remove state file: {e}")
                
        logging.info("Website blocker stopped")

    def generate_complex_password(self):
        """Generate a complex password and store its hash"""
        try:
            # Generate a 16-character random password with mixed case, numbers, and symbols
            characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
            password = ''.join(random.choice(characters) for _ in range(16))
            
            # Calculate password hash
            self.password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Store hash
            with open(self.password_hash_file, 'w') as f:
                f.write(self.password_hash)
                
            # Split the password into parts and create scrambled clues
            parts = [password[i:i+4] for i in range(0, len(password), 4)]
            clues = []
            
            for part in parts:
                # Create a jumbled version of each part with extra characters
                jumbled = list(part)
                random.shuffle(jumbled)
                # Add some random characters
                jumbled.extend([random.choice(characters) for _ in range(4)])
                random.shuffle(jumbled)
                clues.append(''.join(jumbled))
            
            # Generate a random folder for the clue file to make it harder to find
            random_dir = ''.join(random.choice(string.ascii_lowercase) for _ in range(8))
            clue_dir = os.path.join("/var/lib", random_dir)
            os.makedirs(clue_dir, exist_ok=True)
            
            # Update the clue file path
            self.password_clue_file = os.path.join(clue_dir, ".clue.txt")
            
            # Save clues to a separate hidden file with a hint about the password structure
            clue_content = f"""
# ATTENTION: Password Hint
# This contains scrambled parts of the password
# Each line below contains one part of the password mixed with random characters
# The actual password is 16 characters long, divided into 4 parts of 4 characters each
# You'll need to figure out which 4 characters in each line belong to the password part
# Good luck!

{clues[0]}
{clues[1]}
{clues[2]}
{clues[3]}
"""
            with open(self.password_clue_file, 'w') as f:
                f.write(clue_content)
                
            # Make file readable only by root
            os.chmod(self.password_clue_file, 0o400)
            
            # Create a hint file pointing to the actual clue file
            hint_file = "/etc/website_blocker/.password_location.txt"
            with open(hint_file, 'w') as f:
                f.write(f"Password clues are located at: {self.password_clue_file}")
            os.chmod(hint_file, 0o400)
            
            logging.info("Generated and stored complex password")
            logging.info(f"Password clues stored at: {self.password_clue_file}")
        except Exception as e:
            logging.error(f"Failed to generate complex password: {e}")

    def solve_challenge(self):
        """Present a math challenge that must be solved to disable the blocker early"""
        try:
            print("\n=== FOCUS CHALLENGE ===")
            print("To disable the website blocker, you need to solve these math problems.")
            print("This is to ensure you really want to disable it and are not just procrastinating.")
            
            # Generate 3 math problems of increasing difficulty
            for i in range(3):
                if not self._generate_and_check_problem(i + 1):
                    return False
            
            print("Congratulations! You've passed the challenge.")
            return True
        except Exception as e:
            logging.error(f"Error in math challenge: {e}")
            return False
    
    def _generate_and_check_problem(self, difficulty):
        """Generate a math problem based on difficulty and check the answer"""
        if difficulty == 1:
            # Simple arithmetic
            a = random.randint(10, 99)
            b = random.randint(10, 99)
            operation = random.choice(['+', '-', '*'])
            if operation == '+':
                result = a + b
                problem = f"{a} + {b} = ?"
            elif operation == '-':
                result = a - b
                problem = f"{a} - {b} = ?"
            else:
                a = random.randint(2, 12)
                b = random.randint(2, 12)
                result = a * b
                problem = f"{a} × {b} = ?"
        elif difficulty == 2:
            # More complex arithmetic
            a = random.randint(10, 99)
            b = random.randint(10, 99)
            c = random.randint(1, 20)
            result = a + b * c
            problem = f"{a} + {b} × {c} = ?"
        else:
            # Even more complex
            a = random.randint(50, 200)
            b = random.randint(2, 5)
            result = a ** b
            problem = f"{a} ^ {b} = ?"
        
        # Present the problem and get the answer
        for attempt in range(3):  # Allow 3 attempts per problem
            try:
                answer = int(input(f"Problem {difficulty}/3 ({3-attempt} attempts left): {problem} "))
                if answer == result:
                    print("Correct!")
                    return True
                else:
                    print("Incorrect. Try again.")
            except ValueError:
                print("Please enter a valid number.")
        
        print(f"You've failed to solve problem {difficulty}. The answer was {result}.")
        return False

    def start_traffic_monitor(self, websites):
        """Create and start a script to monitor outbound network traffic for blocked IP addresses"""
        try:
            # Create the traffic monitor script
            script_content = f"""#!/usr/bin/env python3
import socket
import subprocess
import time
import logging
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/website_blocker_traffic.log'),
        logging.StreamHandler()
    ]
)

# List of blocked IPs (will be checked regularly)
BLOCKED_IPS = {list(self.blocked_ips)}
BLOCKED_DOMAINS = {websites}

def update_blocked_ips():
    \"\"\"Periodically update IPs in case DNS records change\"\"\"
    global BLOCKED_IPS
    try:
        for domain in BLOCKED_DOMAINS:
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                BLOCKED_IPS.extend(ips)
                
                # Also try with www prefix
                try:
                    www_ips = socket.gethostbyname_ex(f"www.{{domain}}")[2]
                    BLOCKED_IPS.extend(www_ips)
                except:
                    pass
            except:
                pass
        
        # Remove duplicates
        BLOCKED_IPS = list(set(BLOCKED_IPS))
        logging.info(f"Updated blocked IPs: {{BLOCKED_IPS}}")
    except Exception as e:
        logging.error(f"Error updating blocked IPs: {{e}}")

def check_connections():
    \"\"\"Check for connections to blocked IPs\"\"\"
    try:
        # Use netstat or lsof to check connections
        if sys.platform == 'linux':
            cmd = ["netstat", "-tnp"]
        elif sys.platform == 'darwin':  # macOS
            cmd = ["lsof", "-i", "-n"]
        else:
            logging.error(f"Unsupported platform: {{sys.platform}}")
            return
            
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check if any connection to blocked IPs exists
        for line in result.stdout.splitlines():
            for ip in BLOCKED_IPS:
                if ip in line:
                    logging.warning(f"Detected connection to blocked IP: {{ip}}")
                    # Force block this connection if possible
                    try:
                        if sys.platform == 'linux':
                            # Extract PID if possible (simplified - would need better parsing in practice)
                            parts = line.split()
                            pid = None
                            for part in parts:
                                if '/' in part:
                                    pid = part.split('/')[0]
                                    break
                                    
                            if pid and pid.isdigit():
                                # Kill the process
                                subprocess.run(["kill", "-9", pid], capture_output=True)
                                logging.info(f"Terminated process {{pid}} connecting to blocked IP {{ip}}")
                    except Exception as e:
                        logging.error(f"Error terminating connection: {{e}}")
    except Exception as e:
        logging.error(f"Error checking connections: {{e}}")

# Main monitoring loop
logging.info("Starting traffic monitor")
try:
    while True:
        # Check for connections to blocked IPs
        check_connections()
        
        # Update blocked IPs every 5 minutes
        if int(time.time()) % 300 < 10:  # Run approximately every 5 minutes
            update_blocked_ips()
            
        # Sleep to avoid excessive CPU usage
        time.sleep(10)
except KeyboardInterrupt:
    logging.info("Traffic monitor stopped")
except Exception as e:
    logging.error(f"Traffic monitor error: {{e}}")
"""
            
            # Write the script to disk
            with open(self.traffic_monitor_script, 'w') as f:
                f.write(script_content)
                
            # Make it executable
            os.chmod(self.traffic_monitor_script, 0o755)
            
            # Start the script in the background
            subprocess.Popen([self.traffic_monitor_script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            logging.info("Started traffic monitor")
            return True
        except Exception as e:
            logging.error(f"Failed to start traffic monitor: {e}")
            return False
            
    def stop_traffic_monitor(self):
        """Stop the traffic monitor process"""
        try:
            # Find and kill the traffic monitor process
            if sys.platform == 'linux':
                subprocess.run(["pkill", "-f", self.traffic_monitor_script], capture_output=True)
            elif sys.platform == 'darwin':  # macOS
                subprocess.run(["pkill", "-f", self.traffic_monitor_script], capture_output=True)
                
            logging.info("Stopped traffic monitor")
            
            # Remove the script
            if os.path.exists(self.traffic_monitor_script):
                os.remove(self.traffic_monitor_script)
                
            return True
        except Exception as e:
            logging.error(f"Failed to stop traffic monitor: {e}")
            return False

def run_daemon(duration):
    """Run the website blocker as a daemon"""
    pid_file = '/var/run/website_blocker.pid'
    
    logging.info("Initializing daemon context...")
    
    # Configure daemon context
    context = DaemonContext(
        working_directory='/',
        umask=0o002,
        pidfile=lockfile.FileLock(pid_file),
        detach_process=True,
        # Preserve file descriptors for logging
        files_preserve=[handler.stream.fileno() for handler in logging.getLogger().handlers if hasattr(handler, 'stream')]
    )
    
    # Configure signal handlers
    context.signal_map = {
        signal.SIGTERM: 'terminate',
        signal.SIGINT: 'terminate'
    }
    
    try:
        logging.info("Entering daemon context...")
        with context:
            logging.info("Inside daemon context, starting blocker...")
            blocker = WebsiteBlocker(duration_minutes=duration)
            blocker.run()
    except Exception as e:
        logging.error(f"Failed to start daemon: {e}")
        raise
        
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)

    if len(sys.argv) != 2:
        print("Usage: sudo python3 blocker.py <duration_in_minutes>")
        sys.exit(1)

    try:
        duration = int(sys.argv[1])
        if duration <= 0:
            raise ValueError("Duration must be positive")
    except ValueError as e:
        print(f"Invalid duration: {e}")
        sys.exit(1)
    
    print(f"\n=== WEBSITE BLOCKER STARTING ===")
    print(f"Duration: {duration} minutes")
    print("\nIMPORTANT: A complex random password will be auto-generated.")
    print("This makes it difficult to impulsively disable the blocker.")
    print("\nIf you absolutely need to terminate early, you'll need to:")
    print("1. Use Ctrl+C to trigger the early termination dialogue")
    print("2. Solve math challenges")
    print("3. Navigate a multi-step process to find and decode the password")
    print("4. Enter the correct password")
    print("\nThe password and clues will be stored in random locations on your system.")
    print("This process is designed to be difficult to discourage impulsive termination.")
    print("If you're trying to focus, this is a feature, not a bug!")
    print("\nStarting in 5 seconds... Press Ctrl+C now to abort.")
    print("\nNOTE: If the blocker crashes, run the following command to clean up:")
    print("  sudo /etc/website_blocker/emergency_cleanup.sh")
    
    # Check if another instance is already running
    lock_file = "/var/run/website_blocker.lock"
    try:
        # Try to open and lock the file
        test_fd = os.open(lock_file, os.O_CREAT | os.O_WRONLY | os.O_NONBLOCK)
        fcntl.flock(test_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # If we got here, no other instance is running
        fcntl.flock(test_fd, fcntl.LOCK_UN)
        os.close(test_fd)
    except IOError as e:
        if e.errno in (errno.EACCES, errno.EAGAIN):
            print("\nERROR: Another instance of the website blocker is already running!")
            print("If you believe this is an error, you can remove the lock file:")
            print(f"  sudo rm {lock_file}")
            sys.exit(1)
    except Exception as e:
        print(f"\nERROR: Failed to check for existing instances: {e}")
        sys.exit(1)
    
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        print("\nAborted by user.")
        sys.exit(0)
        
    print("\nStarting website blocker daemon...")
    run_daemon(duration)