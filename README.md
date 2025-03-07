# advancedNetworkBlocker

Script for blocking websites on macOS (Advanced)

Below is an overview of what the script does:

1. Website Blocking Setup

- Reading Sites: It reads a list of websites to block from a file (by default at /etc/website_blocker/block_list.txt). If this file doesn't exist, it creates one with a default list of distracting websites (like facebook.com, twitter.com, etc.).
- Updating Hosts File: The script modifies the system's /etc/hosts file by inserting a block section (demarcated by markers such as # Website Blocker Start and # Website Blocker End). This section contains entries to redirect the blocked websites to localhost (i.e., 127.0.0.1).
- DNS-Level Blocking: As an extra measure, if the system has dnsmasq installed, the script creates a DNS configuration file that redirects requests for the blocked domains to 127.0.0.1.
- Firewall Rules: It also adds firewall rules (using tools like iptables on Linux or pf on macOS) that reject outbound traffic to the IP addresses associated with the blocked websites.
- Traffic Monitor: A separate traffic monitor process is started to continuously check for any network connections to the IPs of blocked websites. If it detects a connection, it can attempt to terminate the associated process.

2. File and Integrity Management

- Backups and Protection: Before modifying anything, it creates a backup of the original /etc/hosts file and later makes both the hosts file and the block list immutable (read-only) to prevent tampering.
- Integrity Checks: The script calculates a SHA-256 hash of the hosts file after making changes and periodically checks the file to see if it has been altered. If modifications or deletions are detected, it restores the file from backup and re-applies the website blocks.

3. Daemon Operation and Self-Restart

- Daemonization: The script is designed to run as a daemon (background process) using the DaemonContext from the daemon package. It uses a PID file (/var/run/website_blocker.pid) to manage the process.
- Restart Mechanism: It creates a restart shell script that will restart the blocker if it is forcefully killed during the active blocking period. A corresponding cron job is set up to check and run this restart script every minute.

4. Blocking Duration

- The blocker is designed to run for a specified duration (in minutes), passed in as a command-line argument when the script is executed.
- It continuously monitors the remaining time, updating logs every minute until the time expires.
- Once the set duration has elapsed, it cleans up by removing the blocking entries, DNS configurations, firewall rules, and stopping the traffic monitor.

5. Early Termination Protection

- Math Challenge: If someone tries to terminate the blocker early (by sending signals such as SIGINT or SIGTERM), the script presents a math challenge with three problems. The difficulty increases with each problem.
- Password Requirement: In addition to solving the math challenge, the user must also locate and decode a complex, auto-generated password. This password is split into four parts and scrambled with extra characters. Clues for the password are stored in a randomly located file (with a hint file helping to locate it).
- This layered process is designed to discourage impulsive termination of the blocker.

6. Usage and Execution

- The script is intended to be run as root (it performs operations such as modifying system files, changing firewall rules, etc.).
- It prints a startup message and waits a few seconds (giving the user a chance to abort) before beginning the blocking operation.
- Usage typically looks like:
  `sudo python3 blocker.py <duration_in_minutes>`
  where the duration determines how long websites are blocked.
