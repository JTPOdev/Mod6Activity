# rbac_system.py - STUDENT TO COMPLETE
import json

class RBACSystem:
    def __init__(self, policy_file='rbac_policy.json'):
        self.policy_file = policy_file
        self.roles = self._load_roles()
        self.users = {}
    
    def _load_roles(self):
        """Load roles and permissions from policy file"""
        # Default roles if file doesn't exist
        default_roles = {
            'guest': ['read_public'],
            'user': ['read_public', 'write_own', 'read_own'],
            'editor': ['read_public', 'write_own', 'read_own', 'edit_public'],
            'admin': ['read_public', 'write_own', 'read_own',
                      'edit_public', 'delete_any', 'manage_users']
        }
        
        # TODO: Try to load from file, use defaults if file not found
        
        # SOLUTION: Attempt to load roles from JSON file
        # If file doesn't exist or is invalid, use default roles
        try:
            with open(self.policy_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # File doesn't exist or is invalid, use defaults
            # Optionally save defaults for future use
            with open(self.policy_file, 'w') as f:
                json.dump(default_roles, f, indent=4)
            return default_roles
    
    def add_user(self, user_id, role='user'):
        """Add a user with specified role"""
        # TODO: Validate role exists
        # TODO: Add user to users dictionary
        
        # SOLUTION:
        # Step 1: Validate that the role exists in our roles dictionary
        if role not in self.roles:
            print(f"Error: Role '{role}' does not exist")
            return False
        
        # Step 2: Add user with the specified role
        self.users[user_id] = {
            'role': role
        }
        print(f"User '{user_id}' added with role '{role}'")
        return True
    
    def check_permission(self, user_id, permission):
        """Check if user has specific permission"""
        # TODO: Find user's role
        # TODO: Check if permission exists in role's permissions
        # TODO: Return True/False
        
        # SOLUTION:
        # Step 1: Check if user exists
        if user_id not in self.users:
            return False
        
        # Step 2: Get user's role
        user_role = self.users[user_id]['role']
        
        # Step 3: Get permissions for this role
        if user_role not in self.roles:
            return False
        
        role_permissions = self.roles[user_role]
        
        # Step 4: Check if the requested permission is in the role's permissions
        return permission in role_permissions
    
    def can_access_file(self, user_id, filename, action='read'):
        """Check if user can perform action on file"""
        # Define file types and required permissions
        file_permissions = {
            'public.txt': {'read': 'read_public', 'write': 'edit_public'},
            f'{user_id}_private.txt': {'read': 'read_own', 'write': 'write_own'},
            'admin_logs.txt': {'read': 'delete_any', 'write': 'manage_users'}
        }
        
        # TODO: Determine required permission for this file/action
        # TODO: Use check_permission to verify
        
        # SOLUTION:
        # Step 1: Check if the file has defined permissions
        if filename in file_permissions:
            # Get the required permission for this action
            action_permissions = file_permissions[filename]
            if action in action_permissions:
                required_permission = action_permissions[action]
                # Step 2: Use check_permission to verify access
                return self.check_permission(user_id, required_permission)
        
        # Special handling for user-specific private files
        # Check if this is another user's private file
        if filename.endswith('_private.txt'):
            # Extract the owner from filename
            owner = filename.replace('_private.txt', '')
            if owner != user_id:
                # Trying to access someone else's private file
                # Only admins with 'delete_any' can do this
                return self.check_permission(user_id, 'delete_any')
            else:
                # It's the user's own file
                if action == 'read':
                    return self.check_permission(user_id, 'read_own')
                elif action == 'write':
                    return self.check_permission(user_id, 'write_own')
        
        # Default: deny access for undefined files
        return False
    
    def list_users(self):
        """List all users and their roles"""
        # TODO: Return formatted list of users
        
        # SOLUTION: Create a formatted string listing all users
        if not self.users:
            return "No users in system"
        
        result = []
        for user_id, data in self.users.items():
            role = data['role']
            permissions = self.roles.get(role, [])
            result.append(f"  {user_id}: {role} ({', '.join(permissions)})")
        
        return "\n".join(result)


# Sample data to test with
sample_users = [
    ('guest1', 'guest'),
    ('user1', 'user'),
    ('editor1', 'editor'),
    ('admin1', 'admin')
]
