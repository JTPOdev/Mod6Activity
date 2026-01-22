# file_encryptor.py - STUDENT TO COMPLETE
import os
import hashlib
from base64 import b64encode, b64decode

class FileEncryptor:
    def __init__(self, key):
        """
        Initialize with encryption key
        key: String password (will be hashed to 32 bytes)
        """
        # TODO: Convert key string to 32-byte key using SHA-256
        
        # SOLUTION: Hash the key string using SHA-256 to get a fixed 32-byte key
        # This ensures consistent key length regardless of password length
        # digest() returns bytes (32 bytes for SHA-256)
        self.key = hashlib.sha256(key.encode()).digest()
    
    def _xor_encrypt(self, data, key):
        """Simple XOR encryption (for learning purposes)"""
        # TODO: Implement XOR encryption
        # Hint: For each byte in data, XOR with key byte
        # Use modulo to cycle through key bytes
        
        # SOLUTION: XOR each byte of data with corresponding key byte
        # When we reach the end of key, wrap around using modulo
        # XOR is symmetric: encrypt(encrypt(data)) = data
        result = bytearray()
        for i, byte in enumerate(data):
            # Cycle through key bytes using modulo
            key_byte = key[i % len(key)]
            # XOR the data byte with the key byte
            result.append(byte ^ key_byte)
        return bytes(result)
    
    def _pad_data(self, data, block_size=16):
        """Add PKCS7 padding"""
        # TODO: Implement PKCS7 padding
        # Calculate padding_length = block_size - (len(data) % block_size)
        # Create padding bytes where each byte = padding_length
        # Return data + padding
        
        # SOLUTION: PKCS7 padding adds N bytes of value N
        # where N is the number of bytes needed to reach block_size
        # If data is already a multiple of block_size, add a full block
        padding_length = block_size - (len(data) % block_size)
        # Create padding: each byte has value equal to padding_length
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, data):
        """Remove PKCS7 padding"""
        # TODO: Implement PKCS7 unpadding
        # Get padding_length from last byte
        # Validate padding (all padding bytes should equal padding_length)
        # Return data without padding
        
        # SOLUTION: Read the last byte to determine padding length
        # Validate that all padding bytes have the correct value
        # Remove the padding bytes
        if not data:
            return data
        
        # Last byte tells us the padding length
        padding_length = data[-1]
        
        # Validate padding - all padding bytes should equal padding_length
        for i in range(1, padding_length + 1):
            if data[-i] != padding_length:
                raise ValueError("Invalid padding")
        
        # Remove padding and return
        return data[:-padding_length]
    
    def encrypt_file(self, input_path, output_path):
        """Encrypt a file"""
        try:
            # TODO: Complete encryption
            # 1. Read input file
            # 2. Pad data to multiple of block size
            # 3. Encrypt using _xor_encrypt
            # 4. Write to output file
            # 5. Return success status
            
            # SOLUTION:
            # Step 1: Read the input file in binary mode
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Step 2: Apply PKCS7 padding
            padded_data = self._pad_data(data)
            
            # Step 3: Encrypt the padded data
            encrypted_data = self._xor_encrypt(padded_data, self.key)
            
            # Step 4: Write encrypted data to output file
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Step 5: Return success
            return True
            
        except Exception as e:
            print(f"Encryption error: {e}")
            return False
    
    def decrypt_file(self, input_path, output_path):
        """Decrypt a file"""
        try:
            # TODO: Complete decryption
            # 1. Read encrypted file
            # 2. Decrypt using _xor_encrypt (XOR is symmetric)
            # 3. Remove padding using _unpad_data
            # 4. Write to output file
            # 5. Return success status
            
            # SOLUTION:
            # Step 1: Read the encrypted file
            with open(input_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Step 2: Decrypt (XOR is symmetric - same operation)
            decrypted_data = self._xor_encrypt(encrypted_data, self.key)
            
            # Step 3: Remove PKCS7 padding
            unpadded_data = self._unpad_data(decrypted_data)
            
            # Step 4: Write decrypted data to output file
            with open(output_path, 'wb') as f:
                f.write(unpadded_data)
            
            # Step 5: Return success
            return True
            
        except Exception as e:
            print(f"Decryption error: {e}")
            return False
    
    def create_test_file(self, content, filename):
        """Create a test file with given content"""
        # TODO: Create a file with the given content
        
        # SOLUTION: Write the content to a new file
        with open(filename, 'w') as f:
            f.write(content)
