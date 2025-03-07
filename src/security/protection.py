#!/usr/bin/env python3
import os
import sys
import random
import string
import hashlib
import getpass
import logging
import subprocess
import platform

class SecurityProtection:
    def __init__(self, password_hash_file="/etc/website_blocker/password_hash.txt", 
                password_clue_file="/etc/website_blocker/.password_clue.txt"):
        self.password_hash_file = password_hash_file
        self.password_clue_file = password_clue_file
        self.password_hash = None
        self.os_type = platform.system().lower()
    
    def protect_files(self, protect=True):
        """Make hosts file and block list immutable to prevent tampering"""
        hosts_path = "/etc/hosts"
        block_list_path = "/etc/website_blocker/block_list.txt"
        
        if protect:
            action = "protect"
            flag = "+i"  # Set immutable flag
        else:
            action = "unprotect"
            flag = "-i"  # Remove immutable flag
        
        # Linux: use chattr
        if self.os_type == "linux" and os.path.exists("/usr/bin/chattr"):
            try:
                for file_path in [hosts_path, block_list_path]:
                    if os.path.exists(file_path):
                        subprocess.run(["chattr", flag, file_path], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE)
                logging.info(f"Files {action}ed using chattr")
                return True
            except Exception as e:
                logging.error(f"Failed to {action} files with chattr: {e}")
                return False
        
        # macOS: use chflags
        elif self.os_type == "darwin" and os.path.exists("/usr/bin/chflags"):
            try:
                macos_flag = "uimmutable" if protect else "nouimmutable"
                for file_path in [hosts_path, block_list_path]:
                    if os.path.exists(file_path):
                        subprocess.run(["chflags", macos_flag, file_path], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE)
                logging.info(f"Files {action}ed using chflags")
                return True
            except Exception as e:
                logging.error(f"Failed to {action} files with chflags: {e}")
                return False
        
        else:
            logging.warning(f"File protection not supported on this system ({self.os_type})")
            return False
    
    def generate_complex_password(self):
        """Generate a complex random password and save its hash"""
        # Create parent directory if it doesn't exist
        parent_dir = os.path.dirname(self.password_hash_file)
        if not os.path.exists(parent_dir):
            try:
                os.makedirs(parent_dir, exist_ok=True)
            except Exception as e:
                logging.error(f"Failed to create password directory: {e}")
                return False
        
        # Generate a random password
        length = random.randint(12, 16)
        uppercase_letters = string.ascii_uppercase
        lowercase_letters = string.ascii_lowercase
        digits = string.digits
        special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
        
        # Ensure at least one character from each category
        password = [
            random.choice(uppercase_letters),
            random.choice(lowercase_letters),
            random.choice(digits),
            random.choice(special_chars)
        ]
        
        # Fill the rest randomly
        all_chars = uppercase_letters + lowercase_letters + digits + special_chars
        for _ in range(length - 4):
            password.append(random.choice(all_chars))
        
        # Shuffle the password characters
        random.shuffle(password)
        password = ''.join(password)
        
        # Create a hash of the password
        self.password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            # Save the password hash to a file
            with open(self.password_hash_file, 'w') as f:
                f.write(self.password_hash)
                
            # Create a password clue by showing only a portion of the password
            clue_length = min(4, len(password) // 3)
            start_idx = random.randint(0, len(password) - clue_length)
            password_clue = "..." + password[start_idx:start_idx + clue_length] + "..."
            
            # Save the password clue to a hidden file
            with open(self.password_clue_file, 'w') as f:
                f.write(password_clue)
                
            logging.info(f"Generated and saved password hash. Password clue: {password_clue}")
            print(f"IMPORTANT: Remember this password to unlock the blocker: {password}")
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to save password hash: {e}")
            return False
    
    def check_password(self, password):
        """Check if the provided password matches the stored hash"""
        if not self.password_hash:
            try:
                with open(self.password_hash_file, 'r') as f:
                    self.password_hash = f.read().strip()
            except Exception as e:
                logging.error(f"Failed to read password hash: {e}")
                return False
                
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        return input_hash == self.password_hash
    
    def solve_challenge(self):
        """Require the user to solve a math problem as an additional barrier"""
        print("\nTo unlock the website blocker, you need to solve a math problem.")
        print("This is designed to make it harder to impulsively disable the blocker.")
        
        # Start with easy difficulty
        difficulty = 1
        max_attempts = 3
        
        # Try up to 3 difficulties
        for _ in range(3):
            correct = self._generate_and_check_problem(difficulty)
            if correct:
                return True
            difficulty += 1
        
        print("Too many failed attempts. Please try again later.")
        return False
    
    def _generate_and_check_problem(self, difficulty):
        """Generate and check a math problem of the given difficulty"""
        max_attempts = 3
        attempts = 0
        
        while attempts < max_attempts:
            attempts += 1
            
            if difficulty == 1:
                # Simple addition/subtraction
                a = random.randint(10, 50)
                b = random.randint(10, 50)
                op = random.choice(["+", "-"])
                expression = f"{a} {op} {b}"
                expected = a + b if op == "+" else a - b
                
            elif difficulty == 2:
                # Multiplication/division
                a = random.randint(5, 20)
                b = random.randint(3, 10)
                product = a * b
                if random.choice([True, False]):
                    expression = f"{a} × {b}"
                    expected = product
                else:
                    expression = f"{product} ÷ {b}"
                    expected = a
                    
            else:  # difficulty 3
                # Multiple operations with parentheses
                a = random.randint(5, 20)
                b = random.randint(3, 10)
                c = random.randint(5, 15)
                if random.choice([True, False]):
                    expression = f"({a} + {b}) × {c}"
                    expected = (a + b) * c
                else:
                    expression = f"{a} × {b} - {c}"
                    expected = a * b - c
            
            try:
                print(f"\nSolve: {expression} = ?")
                print(f"Attempt {attempts}/{max_attempts}")
                answer = input("Your answer: ")
                if answer.strip() == str(expected):
                    print("Correct! Challenge solved.")
                    return True
                else:
                    print(f"Incorrect. The answer was {expected}.")
            except (ValueError, KeyboardInterrupt):
                print("Invalid input.")
        
        print(f"Failed difficulty level {difficulty}.")
        return False 