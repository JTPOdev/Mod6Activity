# password_manager.py - STUDENT TO COMPLETE
import hashlib
import os
import json
import secrets

class PasswordManager:
    def __init__(self, storage_file='passwords.json'):
        self.storage_file = storage_file
        self.users = self._load_users()
    
    def _load_users(self):
        """Load users from storage file"""
        # TODO: Complete this method
        # Hint: Use json.load() and handle FileNotFoundError
        
        # SOLUTION: Try to open and load the JSON file
        # If the file doesn't exist, return an empty dictionary
        try:
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # File doesn't exist yet, return empty dict
            return {}
        except json.JSONDecodeError:
            # File is corrupted or empty, return empty dict
            return {}
    
    def _save_users(self):
        """Save users to storage file"""
        # TODO: Complete this method
        # Hint: Use json.dump() with indent=4
        
        # SOLUTION: Write the users dictionary to the JSON file
        # Using indent=4 for readable formatting
        with open(self.storage_file, 'w') as f:
            json.dump(self.users, f, indent=4)
    
    def hash_password(self, password, salt=None):
        """
        Hash a password using SHA-256 with salt
        Returns: (hashed_password, salt_used)
        """
        if salt is None:
            salt = secrets.token_hex(16)  # Generate random salt
        
        # TODO: Complete this method
        # Hint: Use hashlib.sha256()
        # Combine salt + password, then hash
        
        # SOLUTION: Concatenate salt and password, then hash using SHA-256
        # The salt is prepended to the password before hashing
        # This prevents rainbow table attacks
        salted_password = salt + password
        hashed = hashlib.sha256(salted_password.encode()).hexdigest()
        return (hashed, salt)
    
    def verify_password(self, password, stored_hash, salt):
        """Verify if password matches stored hash"""
        # TODO: Complete this method
        # Hint: Hash the input password with the same salt
        # Compare with stored_hash
        
        # SOLUTION: Re-hash the provided password with the stored salt
        # If the resulting hash matches the stored hash, password is correct
        computed_hash, _ = self.hash_password(password, salt)
        return computed_hash == stored_hash
    
    def add_user(self, username, password, role='user'):
        """Add a new user with hashed password"""
        # TODO: Complete this method
        # 1. Check if username already exists
        # 2. Hash the password with a new salt
        # 3. Store username, hashed password, salt, and role
        # 4. Save to file
        
        # SOLUTION: 
        # Step 1: Check if user already exists
        if username in self.users:
            print(f"Error: User '{username}' already exists")
            return False
        
        # Step 2: Hash the password (salt is auto-generated)
        hashed_password, salt = self.hash_password(password)
        
        # Step 3: Store user data in dictionary
        self.users[username] = {
            'password_hash': hashed_password,
            'salt': salt,
            'role': role
        }
        
        # Step 4: Persist to file
        self._save_users()
        print(f"User '{username}' added successfully with role '{role}'")
        return True
    
    def authenticate(self, username, password):
        """Authenticate a user"""
        # TODO: Complete this method
        # 1. Find user by username
        # 2. Verify password
        # 3. Return (success, role) or (False, None)
        
        # SOLUTION:
        # Step 1: Check if user exists
        if username not in self.users:
            return (False, None)
        
        # Step 2: Get stored credentials and verify password
        user_data = self.users[username]
        stored_hash = user_data['password_hash']
        salt = user_data['salt']
        
        if self.verify_password(password, stored_hash, salt):
            # Step 3: Return success with role
            return (True, user_data['role'])
        else:
            return (False, None)
    
    def change_password(self, username, old_password, new_password):
        """Change user password"""
        # TODO: Complete this method
        # 1. Verify old password
        # 2. Hash new password with new salt
        # 3. Update stored credentials
        
        # SOLUTION:
        # Step 1: Verify the old password first
        success, role = self.authenticate(username, old_password)
        if not success:
            print("Error: Old password is incorrect")
            return False
        
        # Step 2: Generate new hash with new salt
        new_hash, new_salt = self.hash_password(new_password)
        
        # Step 3: Update user's credentials
        self.users[username]['password_hash'] = new_hash
        self.users[username]['salt'] = new_salt
        
        # Save changes
        self._save_users()
        print(f"Password changed successfully for '{username}'")
        return True
