#!/usr/bin/env python3
import os
import sys
import argparse
import logging
from daemon.daemon import DaemonContext
import lockfile

from src.core.blocker import WebsiteBlocker

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Block distracting websites for a specified duration')
    parser.add_argument('--duration', type=int, help='Duration in minutes to block websites', required=True)
    parser.add_argument('--daemon', action='store_true', help='Run as a daemon in the background')
    return parser.parse_args()

def run_daemon(duration):
    """Run the website blocker as a daemon"""
    # Set up the daemon context
    pid_file = "/var/run/website_blocker.pid"
    
    # Create parent directory for PID file if it doesn't exist
    pid_dir = os.path.dirname(pid_file)
    if not os.path.exists(pid_dir):
        try:
            os.makedirs(pid_dir, exist_ok=True)
        except Exception as e:
            logging.error(f"Failed to create PID directory: {e}")
            sys.exit(1)
            
    # Create the daemon context
    with DaemonContext(
        pidfile=lockfile.FileLock(pid_file),
        detach_process=True,
        stdout=sys.stdout,
        stderr=sys.stderr,
        umask=0o022
    ):
        blocker = WebsiteBlocker(duration_minutes=duration)
        blocker.run()

def run_foreground(duration):
    """Run the website blocker in the foreground"""
    blocker = WebsiteBlocker(duration_minutes=duration)
    blocker.run()

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/website_blocker.log'),
            logging.StreamHandler()
        ]
    )
    
    # Run in daemon or foreground mode
    if args.daemon:
        run_daemon(args.duration)
    else:
        run_foreground(args.duration)

if __name__ == "__main__":
    main() 