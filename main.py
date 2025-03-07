#!/usr/bin/env python3
"""
Website Blocker - Block distracting websites for a specified duration.

This application helps you focus by blocking access to specified websites for a set duration.
It modifies your system's hosts file and (optionally) uses DNS and firewall-level blocking.

Usage:
    python main.py --duration 120  # Block websites for 120 minutes
    python main.py --duration 60 --daemon  # Run in daemon mode for 60 minutes
"""

from src.utils.daemon import main

if __name__ == "__main__":
    main() 