# Activity6_setup_check.py
import sys
import os

def check_environment():
    print("=" * 60)
    print("Activity 6: ENVIRONMENT CHECK")
    print("=" * 60)
    
    # Check Python version
    print(f"✓ Python Version: {sys.version}")
    
    # Check current directory
    print(f"✓ Current Directory: {os.getcwd()}")
    
    # Check for required modules
    required_modules = ['hashlib', 'os', 'json', 'base64']
    print("\nChecking required modules:")
    for module in required_modules:
        try:
            __import__(module)
            print(f"  ✓ {module}")
        except ImportError:
            print(f"  ✗ {module} - MISSING")
    
    # Optional advanced modules
    print("\nOptional modules (for bonus tasks):")
    optional_modules = ['Crypto', 'bcrypt', 'getpass']
    for module in optional_modules:
        try:
            __import__(module)
            print(f"  ✓ {module} - AVAILABLE")
        except ImportError:
            print(f"  ✗ {module} - Not installed (ok for basic tasks)")
    
    print("\n" + "=" * 60)
    print("ENVIRONMENT CHECK COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    check_environment()
