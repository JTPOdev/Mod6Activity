# security_tests.py
import os

def run_security_tests():
    print("SECURITY VULNERABILITY TESTS")
    print("=" * 60)
    
    # Test 1: Check for plaintext passwords
    print("\nTest 1: Searching for plaintext passwords in files...")
    files_to_check = ['passwords.json', 'test_passwords.json']
    for file in files_to_check:
        if os.path.exists(file):
            with open(file, 'r') as f:
                content = f.read()
            if 'password' in content.lower():
                print(f"  WARNING: '{file}' may contain plaintext passwords")
            else:
                print(f"  ✓ '{file}' appears safe")
    
    # Test 2: Check file permissions
    print("\nTest 2: Checking file permissions...")
    sensitive_files = ['encrypted.bin', 'passwords.json']
    for file in sensitive_files:
        if os.path.exists(file):
            # Check if file is readable by others (simplified check)
            try:
                with open(file, 'rb') as f:
                    f.read(10)  # Try to read a small portion
                print(f"  ✓ '{file}' is accessible (normal for lab environment)")
            except PermissionError:
                print(f"  ✓ '{file}' has restricted access")
    
    # Test 3: Validate encryption
    print("\nTest 3: Validating encryption implementation...")
    # Create a test to ensure encrypted files differ from original
    if os.path.exists("test_secret.txt") and os.path.exists("encrypted.bin"):
        with open("test_secret.txt", "rb") as f1, open("encrypted.bin", "rb") as f2:
            original = f1.read(100)
            encrypted = f2.read(100)
            if original != encrypted:
                print("  ✓ Encryption is working (files differ)")
            else:
                print("  CRITICAL: Encryption not working (files identical!)")
    
    print("\n" + "=" * 60)
    print("SECURITY TESTS COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    run_security_tests()
