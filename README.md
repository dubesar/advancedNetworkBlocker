# advancedNetworkBlocker

Script for blocking websites on macOS and Linux with advanced features.

## Overview

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

- When run with the --daemon flag, the script operates as a background service, continuously monitoring and enforcing the website blocks for the specified duration.
- A restart script is created that can relaunch the blocker if the process is killed, ensuring that the blocks remain in effect for the full duration.

4. Security Features

- Password Protection: The script generates a random, complex password during startup. This password is required to disable the blocker before the specified duration expires.
- Challenge Puzzle: As an additional deterrent, the user must solve a math problem to disable the blocker early, making it harder to impulsively disable the blocks.

## Code Structure

The code is organized into the following components:

```
src/
├── core/                  # Core blocker functionality
│   └── blocker.py         # Main WebsiteBlocker class
├── file_handlers/         # File management operations
│   ├── block_list.py      # Block list reading/writing
│   └── hosts_file.py      # Hosts file manipulation
├── network/               # Network-related operations
│   ├── dns_handler.py     # DNS blocking functionality
│   └── firewall_handler.py # Firewall rule management
├── security/              # Security features
│   └── protection.py      # Password protection and file integrity
└── utils/                 # Utility functions
    └── daemon.py          # Daemon functionality
```

## Usage

1. Install dependencies:

```
pip install -r requirements.txt
```

2. Run the script (requires root/sudo access):

```
sudo python main.py --duration 120  # Block websites for 120 minutes
sudo python main.py --duration 60 --daemon  # Run in daemon mode for 60 minutes
```

## Requirements

- Python 3.6+
- python-daemon>=2.3.0
- lockfile>=0.12.2

## Platform Support

- macOS: Full support including hosts file modification, pf firewall rules
- Linux: Full support including hosts file modification, iptables/nftables firewall rules

## License

See the LICENSE file for details.
