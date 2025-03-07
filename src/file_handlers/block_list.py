#!/usr/bin/env python3
import os
import sys
import logging

class BlockListHandler:
    def __init__(self, block_list_path="/etc/website_blocker/block_list.txt"):
        self.block_list_path = block_list_path
        
        # Ensure block list directory exists
        self._ensure_block_list_directory()
    
    def _ensure_block_list_directory(self):
        """Create block list directory if it doesn't exist"""
        block_list_dir = os.path.dirname(self.block_list_path)
        if not os.path.exists(block_list_dir):
            try:
                os.makedirs(block_list_dir, exist_ok=True)
                logging.info(f"Created block list directory: {block_list_dir}")
            except Exception as e:
                logging.error(f"Failed to create block list directory: {e}")
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
                "pinterest.com",
                "twitch.tv",
                "discord.com",
                "hulu.com",
                "disneyplus.com"
            ]
            
            with open(self.block_list_path, 'w') as f:
                f.write('\n'.join(default_sites))
            
            logging.info(f"Created default block list at {self.block_list_path}")
            
        except Exception as e:
            logging.error(f"Failed to create default block list: {e}")
    
    def add_to_block_list(self, websites):
        """Add websites to the block list"""
        if not websites:
            return
            
        current_websites = set(self.read_block_list())
        
        # Add new websites
        new_websites = set(websites) - current_websites
        if not new_websites:
            logging.info("No new websites to add to block list")
            return
            
        try:
            with open(self.block_list_path, 'a') as f:
                for website in new_websites:
                    f.write(f"\n{website}")
            
            logging.info(f"Added {len(new_websites)} websites to block list")
            
        except Exception as e:
            logging.error(f"Failed to add websites to block list: {e}")
    
    def remove_from_block_list(self, websites):
        """Remove websites from the block list"""
        if not websites:
            return
            
        current_websites = self.read_block_list()
        websites_to_remove = set(websites)
        
        try:
            # Read the entire file with comments
            with open(self.block_list_path, 'r') as f:
                lines = f.readlines()
                
            # Write back all lines except those containing websites to remove
            with open(self.block_list_path, 'w') as f:
                for line in lines:
                    stripped_line = line.strip()
                    if (stripped_line in websites_to_remove or 
                        (stripped_line and not stripped_line.startswith('#') and stripped_line in websites_to_remove)):
                        continue
                    f.write(line)
            
            logging.info(f"Removed websites from block list")
            
        except Exception as e:
            logging.error(f"Failed to remove websites from block list: {e}") 