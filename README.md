# Activity 6 Report: Data Security Implementation
## Information Assurance and Security 2

---

## Part 1: Environment Setup

### File: `Activity6_setup_check.py`

**Purpose:** Verifies that the Python environment has all required modules for the security lab.

**How it works:**
- Checks Python version using `sys.version`
- Displays current working directory using `os.getcwd()`
- Tests required modules (`hashlib`, `os`, `json`, `base64`) using `__import__()`
- Tests optional advanced modules (`Crypto`, `bcrypt`, `getpass`)

**Key Code Section:**
```python
required_modules = ['hashlib', 'os', 'json', 'base64']
for module in required_modules:
    try:
        __import__(module)
        print(f"  ✓ {module}")
    except ImportError:
        print(f"  ✗ {module} - MISSING")
```

---

## Part 2: Password Hashing Implementation

### File: `password_manager.py`

**Purpose:** Implements secure password storage using SHA-256 hashing with salt.

### Completed TODO Sections:

#### 1. `_load_users()` Method
**What it does:** Loads user data from a JSON file.

```python
try:
    with open(self.storage_file, 'r') as f:
        return json.load(f)
except FileNotFoundError:
    return {}
except json.JSONDecodeError:
    return {}
```

**Explanation:** Uses `json.load()` to parse the file. Handles `FileNotFoundError` for first-time use and `JSONDecodeError` for corrupted files by returning an empty dictionary.

---

#### 2. `_save_users()` Method
**What it does:** Persists user data to JSON file.

```python
with open(self.storage_file, 'w') as f:
    json.dump(self.users, f, indent=4)
```

**Explanation:** Uses `json.dump()` with `indent=4` for human-readable formatting.

---

#### 3. `hash_password()` Method
**What it does:** Creates a secure hash of a password using SHA-256 with salt.

```python
salted_password = salt + password
hashed = hashlib.sha256(salted_password.encode()).hexdigest()
return (hashed, salt)
```

**Explanation:** 
- Concatenates salt (16 random hex characters) with the password
- Applies SHA-256 hashing using `hashlib.sha256()`
- Returns the hash as hexadecimal string along with the salt used
- Salt prevents rainbow table attacks

---

#### 4. `verify_password()` Method
**What it does:** Verifies if a provided password matches the stored hash.

```python
computed_hash, _ = self.hash_password(password, salt)
return computed_hash == stored_hash
```

**Explanation:** Re-hashes the input password with the stored salt and compares the result with the stored hash.

---

#### 5. `add_user()` Method
**What it does:** Registers a new user with hashed credentials.

```python
if username in self.users:
    return False
hashed_password, salt = self.hash_password(password)
self.users[username] = {
    'password_hash': hashed_password,
    'salt': salt,
    'role': role
}
self._save_users()
```

**Explanation:** Checks for duplicates, generates hash with new salt, stores credentials, and persists to file.

---

#### 6. `authenticate()` Method
**What it does:** Validates user login credentials.

```python
if username not in self.users:
    return (False, None)
user_data = self.users[username]
if self.verify_password(password, user_data['password_hash'], user_data['salt']):
    return (True, user_data['role'])
return (False, None)
```

**Explanation:** Looks up user, verifies password hash, returns success status with role.

---

#### 7. `change_password()` Method
**What it does:** Updates a user's password after verifying the old one.

```python
success, role = self.authenticate(username, old_password)
if not success:
    return False
new_hash, new_salt = self.hash_password(new_password)
self.users[username]['password_hash'] = new_hash
self.users[username]['salt'] = new_salt
self._save_users()
```

**Explanation:** Authenticates with old password first (security check), then generates new hash with new salt.

---

## Part 3: File Encryption System

### File: `file_encryptor.py`

**Purpose:** Implements file encryption using XOR cipher with PKCS7 padding.

### Completed TODO Sections:

#### 1. `__init__()` Method
**What it does:** Initializes the encryptor with a hashed key.

```python
self.key = hashlib.sha256(key.encode()).digest()
```

**Explanation:** Converts any-length password to a fixed 32-byte key using SHA-256. `digest()` returns raw bytes instead of hex string.

---

#### 2. `_xor_encrypt()` Method
**What it does:** Performs XOR encryption (symmetric).

```python
result = bytearray()
for i, byte in enumerate(data):
    key_byte = key[i % len(key)]
    result.append(byte ^ key_byte)
return bytes(result)
```

**Explanation:** 
- XORs each data byte with corresponding key byte
- Uses modulo to cycle through key bytes when data is longer than key
- XOR is symmetric: `encrypt(encrypt(data)) = data`

---

#### 3. `_pad_data()` Method
**What it does:** Applies PKCS7 padding to data.

```python
padding_length = block_size - (len(data) % block_size)
padding = bytes([padding_length] * padding_length)
return data + padding
```

**Explanation:** 
- PKCS7 padding adds N bytes, each with value N
- Ensures data length is multiple of block size (16 bytes)
- Example: If 3 bytes needed, adds `[0x03, 0x03, 0x03]`

---

#### 4. `_unpad_data()` Method
**What it does:** Removes PKCS7 padding after decryption.

```python
padding_length = data[-1]
for i in range(1, padding_length + 1):
    if data[-i] != padding_length:
        raise ValueError("Invalid padding")
return data[:-padding_length]
```

**Explanation:** 
- Reads last byte to determine padding length
- Validates all padding bytes have correct value (security check)
- Removes padding bytes

---

#### 5. `encrypt_file()` Method
**What it does:** Encrypts an entire file.

```python
with open(input_path, 'rb') as f:
    data = f.read()
padded_data = self._pad_data(data)
encrypted_data = self._xor_encrypt(padded_data, self.key)
with open(output_path, 'wb') as f:
    f.write(encrypted_data)
return True
```

**Explanation:** Reads binary data → Pads → Encrypts → Writes to new file.

---

#### 6. `decrypt_file()` Method
**What it does:** Decrypts an encrypted file.

```python
with open(input_path, 'rb') as f:
    encrypted_data = f.read()
decrypted_data = self._xor_encrypt(encrypted_data, self.key)
unpadded_data = self._unpad_data(decrypted_data)
with open(output_path, 'wb') as f:
    f.write(unpadded_data)
return True
```

**Explanation:** Reads encrypted data → Decrypts (XOR is symmetric) → Removes padding → Writes original content.

---

#### 7. `create_test_file()` Method
**What it does:** Creates a test file for encryption testing.

```python
with open(filename, 'w') as f:
    f.write(content)
```

---

## Part 4: RBAC Implementation

### File: `rbac_system.py`

**Purpose:** Implements Role-Based Access Control for file access.

### Role Hierarchy:
| Role | Permissions |
|------|-------------|
| guest | read_public |
| user | read_public, write_own, read_own |
| editor | read_public, write_own, read_own, edit_public |
| admin | read_public, write_own, read_own, edit_public, delete_any, manage_users |

### Completed TODO Sections:

#### 1. `_load_roles()` Method
**What it does:** Loads role definitions from JSON file.

```python
try:
    with open(self.policy_file, 'r') as f:
        return json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    with open(self.policy_file, 'w') as f:
        json.dump(default_roles, f, indent=4)
    return default_roles
```

**Explanation:** Tries to load from file, creates default policy file if not found.

---

#### 2. `add_user()` Method
**What it does:** Adds a user with role validation.

```python
if role not in self.roles:
    return False
self.users[user_id] = {'role': role}
return True
```

**Explanation:** Validates role exists before adding user. Prevents invalid role assignment.

---

#### 3. `check_permission()` Method
**What it does:** Checks if user has specific permission.

```python
if user_id not in self.users:
    return False
user_role = self.users[user_id]['role']
role_permissions = self.roles[user_role]
return permission in role_permissions
```

**Explanation:** Gets user's role → Gets role's permissions → Checks if permission in list.

---

#### 4. `can_access_file()` Method
**What it does:** Checks file access based on file type and action.

```python
if filename in file_permissions:
    action_permissions = file_permissions[filename]
    if action in action_permissions:
        required_permission = action_permissions[action]
        return self.check_permission(user_id, required_permission)
```

**Explanation:** 
- Maps filename + action to required permission
- Uses `check_permission()` to verify
- Handles user-specific private files

---

#### 5. `list_users()` Method
**What it does:** Returns formatted list of all users.

```python
result = []
for user_id, data in self.users.items():
    role = data['role']
    permissions = self.roles.get(role, [])
    result.append(f"  {user_id}: {role} ({', '.join(permissions)})")
return "\n".join(result)
```

---

## Part 5: Security Testing

### File: `security_tests.py`

**Purpose:** Validates security implementations against common vulnerabilities.

**Tests Performed:**
1. **Plaintext Password Check** - Scans JSON files for plaintext passwords
2. **File Permission Check** - Verifies sensitive files have proper access
3. **Encryption Validation** - Confirms encrypted files differ from originals

---

## Summary

| Component | Security Feature | Protection Against |
|-----------|-----------------|-------------------|
| Password Manager | SHA-256 + Salt | Rainbow table attacks |
| File Encryptor | XOR + PKCS7 Padding | Data interception |
| RBAC System | Role-based permissions | Unauthorized access |
| Security Tests | Vulnerability scanning | Common attack vectors |
