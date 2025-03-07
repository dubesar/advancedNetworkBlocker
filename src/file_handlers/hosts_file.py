#!/usr/bin/env python3
import os
import sys
import logging
import hashlib

class HostsFileHandler:
    def __init__(self, hosts_path="/etc/hosts", hosts_backup="/etc/hosts.backup", 
                 marker_start="# Website Blocker Start", marker_end="# Website Blocker End"):
        self.hosts_path = hosts_path
        self.hosts_backup = hosts_backup
        self.marker_start = marker_start
        self.marker_end = marker_end
        self.hosts_file_hash = None
    
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
    
    def update_hosts(self, websites, blocking=True):
        """Update the hosts file to block or unblock websites"""
        if not websites:
            logging.error("No websites provided to update hosts file")
            return False

        try:
            with open(self.hosts_path, 'r') as f:
                hosts_content = f.read()

            # Remove existing block section if present
            if self.marker_start in hosts_content and self.marker_end in hosts_content:
                start_idx = hosts_content.find(self.marker_start)
                end_idx = hosts_content.find(self.marker_end) + len(self.marker_end)
                hosts_content = hosts_content[:start_idx] + hosts_content[end_idx:]

            # Add new block section if we're blocking
            if blocking:
                block_section = [self.marker_start]
                block_section.append("# This section is automatically managed by the website blocker")
                block_section.append("# Do not edit manually")
                
                # Add entries for each website with both the domain and www subdomain
                for website in websites:
                    website = website.strip()
                    if website and not website.startswith('#'):
                        block_section.append(f"127.0.0.1 {website}")
                        if not website.startswith('www.'):
                            block_section.append(f"127.0.0.1 www.{website}")
                
                block_section.append(self.marker_end)
                
                # Add the block section to the hosts file
                hosts_content += "\n" + "\n".join(block_section) + "\n"

            # Write the updated hosts file
            with open(self.hosts_path, 'w') as f:
                f.write(hosts_content)

            # Update the hash after modifying the file
            self.hosts_file_hash = self.calculate_file_hash(self.hosts_path)
            
            if blocking:
                logging.info(f"Blocked {len(websites)} websites in hosts file")
            else:
                logging.info("Removed website blocks from hosts file")
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to update hosts file: {e}")
            return False
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            return file_hash
        except Exception as e:
            logging.error(f"Failed to calculate file hash: {e}")
            return None
    
    def check_hosts_file_integrity(self, websites):
        """Check if hosts file has been tampered with"""
        if not self.hosts_file_hash:
            logging.error("No initial hash available to check integrity")
            return
            
        current_hash = self.calculate_file_hash(self.hosts_path)
        
        if not current_hash:
            logging.warning("Hosts file may have been deleted, restoring...")
            self.restore_hosts_file(websites)
            return
            
        if current_hash != self.hosts_file_hash:
            logging.warning("Hosts file has been modified, restoring...")
            self.restore_hosts_file(websites)
    
    def restore_hosts_file(self, websites):
        """Restore hosts file from backup and re-apply blocks"""
        try:
            # Check if backup exists
            if not os.path.exists(self.hosts_backup):
                logging.error("Hosts backup file not found, cannot restore")
                return
                
            # Copy backup to hosts file
            with open(self.hosts_backup, 'r') as src, open(self.hosts_path, 'w') as dst:
                dst.write(src.read())
                
            logging.info("Restored hosts file from backup")
            
            # Re-apply website blocks
            self.update_hosts(websites, blocking=True)
            
        except Exception as e:
            logging.error(f"Failed to restore hosts file: {e}") 