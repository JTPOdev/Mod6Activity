# test_file_encryption.py
from file_encryptor import FileEncryptor

def test_encryption():
    # Create encryptor with password
    encryptor = FileEncryptor("MySecretPassword123")
    
    # Test 1: Create and encrypt a file
    print("Test 1: Creating and encrypting test file")
    test_content = "This is a secret message!\nLine 2\nLine 3"
    encryptor.create_test_file(test_content, "test_secret.txt")
    
    # Encrypt the file
    encryptor.encrypt_file("test_secret.txt", "encrypted.bin")
    print("  ✓ File encrypted: encrypted.bin")
    
    # Test 2: Decrypt with correct password
    print("\nTest 2: Decrypting with correct password")
    encryptor2 = FileEncryptor("MySecretPassword123")
    success = encryptor2.decrypt_file("encrypted.bin", "decrypted.txt")
    print(f"  ✓ Decryption successful: {success}")
    
    # Test 3: Verify content matches
    print("\nTest 3: Verifying decrypted content")
    with open("decrypted.txt", "r") as f:
        decrypted_content = f.read()
    print(f"  Original matches decrypted: {test_content == decrypted_content}")
    
    # Test 4: Try wrong password (should fail)
    print("\nTest 4: Testing wrong password")
    wrong_encryptor = FileEncryptor("WrongPassword")
    try:
        wrong_encryptor.decrypt_file("encrypted.bin", "wrong_decrypt.txt")
        print("  ✗ WRONG: Decryption should have failed!")
    except:
        print("  ✓ CORRECT: Decryption failed with wrong password")

if __name__ == "__main__":
    test_encryption()
