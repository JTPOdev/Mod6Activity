# test_rbac.py
from rbac_system import RBACSystem

def test_rbac():
    rbac = RBACSystem()
    
    # Add test users
    test_users = [
        ('guest1', 'guest'),
        ('user1', 'user'),
        ('editor1', 'editor'),
        ('admin1', 'admin')
    ]
    
    for user_id, role in test_users:
        rbac.add_user(user_id, role)
    
    print("Test Cases:")
    print("=" * 60)
    
    # Test Case 1: Guest permissions
    print("\nTest 1: Guest permissions")
    print(f"  Can guest1 read public.txt? {rbac.can_access_file('guest1', 'public.txt', 'read')}")
    print(f"  Can guest1 write to public.txt? {rbac.can_access_file('guest1', 'public.txt', 'write')}")
    
    # Test Case 2: User permissions
    print("\nTest 2: User permissions")
    print(f"  Can user1 read own file? {rbac.can_access_file('user1', 'user1_private.txt', 'read')}")
    print(f"  Can user1 write to own file? {rbac.can_access_file('user1', 'user1_private.txt', 'write')}")
    
    # Test Case 3: Admin permissions
    print("\nTest 3: Admin permissions")
    print(f"  Can admin1 read admin logs? {rbac.can_access_file('admin1', 'admin_logs.txt', 'read')}")
    print(f"  Can admin1 delete any file? {rbac.check_permission('admin1', 'delete_any')}")
    
    # Test Case 4: Permission escalation attempt
    print("\nTest Case 4: Attempt permission escalation")
    print(f"  Can guest1 access admin logs? {rbac.can_access_file('guest1', 'admin_logs.txt', 'read')}")
    print(f"  Can user1 manage users? {rbac.check_permission('user1', 'manage_users')}")
    
    # List all users
    print("\n" + "=" * 60)
    print("All Users in System:")
    print(rbac.list_users())

if __name__ == "__main__":
    test_rbac()
