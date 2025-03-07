#!/usr/bin/env python3
import os
import sys
import time
import signal
import logging
import datetime
import subprocess
import getpass

from src.file_handlers.hosts_file import HostsFileHandler
from src.file_handlers.block_list import BlockListHandler
from src.network.dns_handler import DNSHandler
from src.network.firewall_handler import FirewallHandler
from src.security.protection import SecurityProtection

class WebsiteBlocker:
    def __init__(self, duration_minutes=None):
        # Default paths
        self.pid_file = "/var/run/website_blocker.pid"
        self.restart_script_path = "/etc/website_blocker/restart.sh"
        self.traffic_monitor_script = "/etc/website_blocker/traffic_monitor.py"
        
        # Time tracking
        self.duration_minutes = duration_minutes
        self.start_time = None
        self.start_monotonic = None
        
        # Component initialization
        self.hosts_handler = HostsFileHandler()
        self.block_list_handler = BlockListHandler()
        self.dns_handler = DNSHandler()
        self.security = SecurityProtection()
        self.firewall_handler = FirewallHandler()
        
        # Initialize security (generate password)
        self.security.generate_complex_password()
        
    def time_remaining(self):
        """Calculate remaining time in minutes"""
        if not self.start_monotonic:
            return 0
            
        elapsed = time.monotonic() - self.start_monotonic
        remaining_minutes = self.duration_minutes - (elapsed / 60)
        return max(0, remaining_minutes)
    
    def create_restart_script(self, end_time):
        """Create a script that will restart the blocker if killed"""
        try:
            script_dir = os.path.dirname(self.restart_script_path)
            if not os.path.exists(script_dir):
                os.makedirs(script_dir, exist_ok=True)
                
            # Calculate remaining duration if the script is executed later
            remaining_cmd = f"python3 -c \"import datetime; " \
                           f"print(max(0, (datetime.datetime.fromisoformat('{end_time.isoformat()}') - " \
                           f"datetime.datetime.now()).total_seconds() / 60))\""
            
            with open(self.restart_script_path, 'w') as f:
                f.write("#!/bin/sh\n\n")
                f.write("# This script is automatically generated to restart the website blocker if killed\n\n")
                
                # Add a comment with the end time
                f.write(f"# Blocking end time: {end_time.isoformat()}\n\n")
                
                # Calculate remaining duration and restart if positive
                f.write("# Calculate remaining duration in minutes\n")
                f.write(f"REMAINING_MINUTES=$({remaining_cmd})\n\n")
                
                # Only restart if time remaining
                f.write("if [ $(echo \"$REMAINING_MINUTES > 0\" | bc -l) -eq 1 ]; then\n")
                
                # Get the path to the original script
                f.write("    # Restart the website blocker\n")
                f.write("    SCRIPT_PATH=$(readlink -f \"$0\")\n")
                f.write("    SCRIPT_DIR=$(dirname \"$SCRIPT_PATH\")\n")
                
                # Execute the daemon with remaining duration
                f.write("    echo \"Restarting website blocker with $REMAINING_MINUTES minutes remaining\"\n")
                
                # Get the original command from /proc/cmdline if available, otherwise use a default
                f.write("    if [ -e /proc/$$/cmdline ]; then\n")
                f.write("        ORIGINAL_CMD=$(cat /proc/$$/cmdline | tr '\\0' ' ')\n")
                f.write("        $ORIGINAL_CMD --duration $REMAINING_MINUTES\n")
                f.write("    else\n")
                f.write("        python3 -m website_blocker --daemon --duration $REMAINING_MINUTES\n")
                f.write("    fi\n")
                
                f.write("else\n")
                f.write("    echo \"Website blocking period has ended, not restarting\"\n")
                f.write("fi\n")
            
            # Make the script executable
            os.chmod(self.restart_script_path, 0o755)
            
            logging.info(f"Created restart script: {self.restart_script_path}")
            
        except Exception as e:
            logging.error(f"Failed to create restart script: {e}")
    
    def _signal_handler(self, signum, frame):
        """Handle signals to ensure cleanup or restart on termination"""
        sig_name = signal.Signals(signum).name
        logging.warning(f"Received signal {sig_name} ({signum})")
        
        # Default behavior is to cleanup and exit
        cleanup_and_exit = True
        
        if signum in (signal.SIGTERM, signal.SIGINT):
            # Check if user really wants to quit or terminate accidentally
            try:
                print("\nYou are attempting to terminate the website blocker.")
                
                # Skip verification if no time remaining
                if self.time_remaining() <= 0:
                    print("Blocking period has ended. Cleaning up...")
                    cleanup_and_exit = True
                else:
                    print(f"There are still {self.time_remaining():.1f} minutes remaining.")
                    
                    # Require a password to unlock
                    print("\nEnter password to disable blocking early:")
                    password = getpass.getpass()
                    
                    if self.security.check_password(password):
                        # Additional challenge as a deterrent
                        if self.security.solve_challenge():
                            print("Password and challenge verified. Disabling website blocker.")
                            cleanup_and_exit = True
                        else:
                            print("Challenge failed. Continuing website blocking.")
                            cleanup_and_exit = False
                    else:
                        print("Incorrect password. Continuing website blocking.")
                        cleanup_and_exit = False
                        
            except KeyboardInterrupt:
                print("\nCancelled termination. Continuing website blocking.")
                cleanup_and_exit = False
        
        if cleanup_and_exit:
            self.cleanup()
            sys.exit(0)
        else:
            # If we decide not to exit, just return to continue execution
            return
    
    def cleanup(self):
        """Clean up all changes and restore original state"""
        logging.info("Cleaning up and restoring original system state")
        
        # Remove file protection
        self.security.protect_files(protect=False)
        
        # Stop traffic monitoring if active
        self.stop_traffic_monitor()
        
        # Get websites for restoring/disabling
        websites = self.block_list_handler.read_block_list()
        
        # Remove hosts file blocks
        self.hosts_handler.update_hosts(websites, blocking=False)
        
        # Remove DNS-level blocking
        self.dns_handler.update_dns_blocking(websites, blocking=False)
        
        # Remove firewall rules
        self.firewall_handler.update_firewall_rules(websites, self.dns_handler.blocked_ips, blocking=False)
        
        # Remove PID file if it exists
        if os.path.exists(self.pid_file):
            os.remove(self.pid_file)
            
        # Remove restart script if it exists
        if os.path.exists(self.restart_script_path):
            os.remove(self.restart_script_path)
            
        logging.info("Cleanup completed successfully")
    
    def start_traffic_monitor(self, websites):
        """Start a separate process to monitor and block traffic to websites"""
        try:
            # Create the traffic monitor script
            script_dir = os.path.dirname(self.traffic_monitor_script)
            if not os.path.exists(script_dir):
                os.makedirs(script_dir, exist_ok=True)
                
            # Create a Python script to monitor traffic
            with open(self.traffic_monitor_script, 'w') as f:
                f.write("#!/usr/bin/env python3\n")
                f.write("import subprocess\n")
                f.write("import time\n")
                f.write("import os\n")
                f.write("import signal\n")
                f.write("import sys\n")
                f.write("import logging\n\n")
                
                # Set up logging
                f.write("logging.basicConfig(\n")
                f.write("    level=logging.INFO,\n")
                f.write("    format='%(asctime)s - %(levelname)s - %(message)s',\n")
                f.write("    handlers=[\n")
                f.write("        logging.FileHandler('/var/log/website_blocker_monitor.log'),\n")
                f.write("        logging.StreamHandler()\n")
                f.write("    ]\n")
                f.write(")\n\n")
                
                # Add the list of blocked IPs
                f.write("# List of blocked website IPs\n")
                f.write("BLOCKED_IPS = {\n")
                for ip in self.dns_handler.blocked_ips:
                    f.write(f"    '{ip}',\n")
                f.write("}\n\n")
                
                # Add signal handler for clean termination
                f.write("def signal_handler(signum, frame):\n")
                f.write("    logging.info('Traffic monitor received signal to terminate')\n")
                f.write("    sys.exit(0)\n\n")
                
                f.write("signal.signal(signal.SIGTERM, signal_handler)\n")
                f.write("signal.signal(signal.SIGINT, signal_handler)\n\n")
                
                # Main monitoring function
                f.write("def monitor_traffic():\n")
                f.write("    logging.info('Starting traffic monitoring')\n")
                f.write("    while True:\n")
                f.write("        try:\n")
                
                # Use netstat or ss to check for connections
                f.write("            # Check for connections to blocked IPs\n")
                f.write("            if os.path.exists('/usr/bin/netstat'):\n")
                f.write("                cmd = ['netstat', '-tn']\n")
                f.write("            elif os.path.exists('/usr/bin/ss'):\n")
                f.write("                cmd = ['ss', '-tn']\n")
                f.write("            else:\n")
                f.write("                logging.error('No command available to check connections')\n")
                f.write("                time.sleep(30)\n")
                f.write("                continue\n\n")
                
                f.write("            result = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)\n")
                f.write("            connections = result.stdout.splitlines()\n\n")
                
                # Parse and check connections
                f.write("            # Check each connection\n")
                f.write("            for conn in connections:\n")
                f.write("                # Skip header lines\n")
                f.write("                if not conn.strip() or 'Local Address' in conn or 'LISTEN' in conn:\n")
                f.write("                    continue\n\n")
                
                f.write("                # Extract remote IP from connection\n")
                f.write("                parts = conn.split()\n")
                f.write("                if len(parts) < 5:\n")
                f.write("                    continue\n\n")
                
                f.write("                remote_addr = parts[4]\n")
                f.write("                remote_ip = remote_addr.split(':')[0]\n\n")
                
                # Check if connection is to a blocked IP
                f.write("                # Check if remote IP is blocked\n")
                f.write("                if remote_ip in BLOCKED_IPS:\n")
                f.write("                    # Find the process using the connection\n")
                f.write("                    try:\n")
                f.write("                        local_addr = parts[3]\n")
                f.write("                        lsof_cmd = ['lsof', '-i', f'@{remote_ip}']\n")
                f.write("                        lsof_result = subprocess.run(lsof_cmd, stdout=subprocess.PIPE, text=True)\n")
                f.write("                        processes = lsof_result.stdout.splitlines()\n\n")
                
                f.write("                        # Extract process IDs\n")
                f.write("                        pids = set()\n")
                f.write("                        for proc in processes:\n")
                f.write("                            if remote_ip in proc:\n")
                f.write("                                parts = proc.split()\n")
                f.write("                                if len(parts) > 1:\n")
                f.write("                                    pids.add(parts[1])\n\n")
                
                # Take action against processes
                f.write("                        # Terminate the processes\n")
                f.write("                        for pid in pids:\n")
                f.write("                            try:\n")
                f.write("                                logging.info(f'Killing process {pid} for accessing blocked site {remote_ip}')\n")
                f.write("                                os.kill(int(pid), signal.SIGTERM)\n")
                f.write("                            except Exception as e:\n")
                f.write("                                logging.error(f'Failed to kill process {pid}: {e}')\n")
                
                f.write("                    except Exception as e:\n")
                f.write("                        logging.error(f'Error processing connection to {remote_ip}: {e}')\n\n")
                
                # Sleep between checks
                f.write("            # Sleep for a short time\n")
                f.write("            time.sleep(5)\n\n")
                
                f.write("        except Exception as e:\n")
                f.write("            logging.error(f'Error in traffic monitor: {e}')\n")
                f.write("            time.sleep(10)\n\n")
                
                # Main entry point
                f.write("if __name__ == '__main__':\n")
                f.write("    monitor_traffic()\n")
            
            # Make the script executable
            os.chmod(self.traffic_monitor_script, 0o755)
            
            # Run the monitor in the background
            subprocess.Popen([self.traffic_monitor_script], 
                            stdout=subprocess.PIPE, 
                            stderr=subprocess.PIPE,
                            start_new_session=True)
            
            logging.info("Started traffic monitoring process")
            
        except Exception as e:
            logging.error(f"Failed to start traffic monitor: {e}")
    
    def stop_traffic_monitor(self):
        """Stop the traffic monitoring process"""
        try:
            # Find the traffic monitor process
            ps_cmd = ["ps", "-ef"]
            ps_result = subprocess.run(ps_cmd, stdout=subprocess.PIPE, text=True)
            processes = ps_result.stdout.splitlines()
            
            for proc in processes:
                if self.traffic_monitor_script in proc:
                    # Extract the PID
                    parts = proc.split()
                    if len(parts) > 1:
                        pid = parts[1]
                        try:
                            # Kill the process
                            subprocess.run(["kill", pid], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                            logging.info(f"Stopped traffic monitor process (PID: {pid})")
                        except Exception as e:
                            logging.error(f"Failed to stop traffic monitor process: {e}")
            
            # Remove the script file
            if os.path.exists(self.traffic_monitor_script):
                os.remove(self.traffic_monitor_script)
                logging.info("Removed traffic monitor script")
                
        except Exception as e:
            logging.error(f"Error stopping traffic monitor: {e}")
    
    def run(self):
        """Main daemon loop"""
        print("Running website blocker daemon")
        if not self.duration_minutes:
            logging.error("Duration not specified")
            return

        # Backup hosts file
        self.hosts_handler.backup_hosts()
        
        # Read websites to block
        websites = self.block_list_handler.read_block_list()
        
        if not websites:
            logging.error("No websites to block")
            return

        # Track start time
        self.start_time = datetime.datetime.now()
        self.start_monotonic = time.monotonic()
        end_time = self.start_time + datetime.timedelta(minutes=self.duration_minutes)
        logging.info(f"Starting website blocker for {self.duration_minutes} minutes")
        
        # Create a restart script that will be triggered if the process is killed forcefully
        self.create_restart_script(end_time)

        # Enable blocking
        hosts_updated = self.hosts_handler.update_hosts(websites, blocking=True)
        dns_updated = self.dns_handler.update_dns_blocking(websites, blocking=True)
        
        if hosts_updated:
            # Protect files from tampering
            self.security.protect_files(protect=True)
            
            # Set up firewall rules using the IPs from DNS resolution
            self.firewall_handler.update_firewall_rules(websites, self.dns_handler.blocked_ips, blocking=True)
            
            # Start traffic monitoring
            self.start_traffic_monitor(websites)
            
            # Set up signal handlers
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)
            
            logging.info("Website blocker is now running in active mode")
            
            # Keep checking the time
            while self.time_remaining() > 0:
                remaining = self.time_remaining()
                logging.info(f"{remaining:.1f} minutes remaining")
                
                # Check hosts file integrity
                self.hosts_handler.check_hosts_file_integrity(websites)
                
                time.sleep(60)  # Check every minute

            # Cleanup when time is up
            self.cleanup()
        else:
            logging.error("Failed to update hosts file. Aborting.")
            # Attempt to clean up in case partial changes were made
            self.cleanup() 