# test_password_manager.py
from password_manager import PasswordManager

def test_password_manager():
    pm = PasswordManager('test_passwords.json')
    
    # Test 1: Add user
    print("Test 1: Adding user 'alice'")
    pm.add_user('alice', 'Password123!', 'admin')
    
    # Test 2: Authentication - correct password
    print("\nTest 2: Authenticating with correct password")
    success, role = pm.authenticate('alice', 'Password123!')
    print(f"  Success: {success}, Role: {role}")
    
    # Test 3: Authentication - wrong password
    print("\nTest 3: Authenticating with wrong password")
    success, role = pm.authenticate('alice', 'WrongPassword')
    print(f"  Success: {success}, Role: {role}")
    
    # Test 4: Change password
    print("\nTest 4: Changing password")
    pm.change_password('alice', 'Password123!', 'NewPassword456!')
    
    # Test 5: Verify new password works
    print("\nTest 5: Verifying new password")
    success, role = pm.authenticate('alice', 'NewPassword456!')
    print(f"  Success: {success}, Role: {role}")
    
    # Test 6: Old password should not work
    print("\nTest 6: Old password should fail")
    success, role = pm.authenticate('alice', 'Password123!')
    print(f"  Success: {success} (should be False)")

if __name__ == "__main__":
    test_password_manager()
