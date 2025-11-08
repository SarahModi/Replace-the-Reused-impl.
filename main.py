import os
import json
import hashlib
import secrets
import string
import sqlite3
from pathlib import Path
from getpass import getpass
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64

# ============================================================================
# CONFIG
# ============================================================================
DB_PATH = Path.home() / ".replace_the_reused" / "vault.db"
MASTER_HASH_PATH = Path.home() / ".replace_the_reused" / ".master_hash"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
SALT_SIZE = 32
NONCE_SIZE = 12

# ============================================================================
# PASSWORD GENERATOR
# ============================================================================
class PersonalPasswordGenerator:
    def __init__(self):
        self.uppercase = string.ascii_uppercase
        self.lowercase = string.ascii_lowercase
        self.digits = string.digits
        self.special = "!@#$%^&*-_=+?"
    
    def create_seed(self, words: list) -> str:
        """Create deterministic seed from personal words"""
        combined = "".join(words).lower()
        hash_obj = hashlib.sha256(combined.encode())
        return hash_obj.hexdigest()
    
    def transform_words(self, words: list) -> str:
        """Transform personal words into memorable base"""
        transformed = []
        for word in words:
            if len(word) > 0:
                modified = word[0].upper() + word[1:].lower() if len(word) > 1 else word.upper()
                transformed.append(modified)
        return "".join(transformed)
    
    def generate_password(self, words: list, length: int = 16) -> tuple:
        """Generate strong password from personal words"""
        if length not in [12, 14, 16]:
            raise ValueError("Length must be 12, 14, or 16")
        
        if not words or all(not w.strip() for w in words):
            raise ValueError("Provide at least one word")
        
        seed = self.create_seed(words)
        memorable_base = self.transform_words(words)
        
        password_list = list(memorable_base)
        needed = length - len(password_list)
        
        if needed < 0:
            password_list = password_list[:length]
        else:
            char_pool = self.uppercase + self.lowercase + self.digits + self.special
            
            if needed >= 2:
                password_list.append(secrets.choice(self.digits))
                password_list.append(secrets.choice(self.special))
                needed -= 2
            
            for _ in range(needed):
                password_list.append(secrets.choice(char_pool))
            
            secrets.SystemRandom().shuffle(password_list)
        
        password = "".join(password_list)
        
        has_upper = any(c in self.uppercase for c in password)
        has_lower = any(c in self.lowercase for c in password)
        has_digit = any(c in self.digits for c in password)
        has_special = any(c in self.special for c in password)
        
        strength_score = sum([has_upper, has_lower, has_digit, has_special])
        strength_map = {4: "Very Strong ✓", 3: "Strong ✓", 2: "Moderate", 1: "Weak"}
        strength = strength_map.get(strength_score, "Weak")
        
        return password, strength

# ============================================================================
# ENCRYPTION UTILITIES
# ============================================================================
class CryptoManager:
    @staticmethod
    def derive_key(master_password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(master_password.encode())
    
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> str:
        """Encrypt data with ChaCha20Poly1305"""
        cipher = ChaCha20Poly1305(key)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = cipher.encrypt(nonce, data.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()
    
    @staticmethod
    def decrypt_data(encrypted_data: str, key: bytes) -> str:
        """Decrypt ChaCha20Poly1305 data"""
        cipher = ChaCha20Poly1305(key)
        nonce_ciphertext = base64.b64decode(encrypted_data)
        nonce = nonce_ciphertext[:NONCE_SIZE]
        ciphertext = nonce_ciphertext[NONCE_SIZE:]
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash master password with Argon2"""
        ph = PasswordHasher()
        return ph.hash(password)
    
    @staticmethod
    def verify_password(password: str, hash_value: str) -> bool:
        """Verify master password"""
        ph = PasswordHasher()
        try:
            ph.verify(hash_value, password)
            return True
        except:
            return False

# ============================================================================
# DATABASE MANAGER
# ============================================================================
class VaultDatabase:
    def __init__(self):
        self.init_db()
    
    def init_db(self):
        """Initialize vault database"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT UNIQUE NOT NULL,
                username TEXT NOT NULL,
                password_encrypted TEXT NOT NULL,
                url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()
    
    def add_credential(self, label: str, username: str, password: str, url: str, key: bytes):
        """Add encrypted credential to vault"""
        encrypted_pwd = CryptoManager.encrypt_data(password, key)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO credentials (label, username, password_encrypted, url) VALUES (?, ?, ?, ?)",
                (label, username, encrypted_pwd, url)
            )
            conn.commit()
            print(f"✓ Credential '{label}' saved to vault!")
        except sqlite3.IntegrityError:
            print(f"✗ Label '{label}' already exists!")
        finally:
            conn.close()
    
    def get_credential(self, label: str, key: bytes) -> dict:
        """Retrieve and decrypt credential"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM credentials WHERE label = ?", (label,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        decrypted_pwd = CryptoManager.decrypt_data(row[3], key)
        return {
            "label": row[1],
            "username": row[2],
            "password": decrypted_pwd,
            "url": row[4],
            "created_at": row[5]
        }
    
    def list_credentials(self) -> list:
        """List all credential labels"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT label, url, created_at FROM credentials")
        rows = cursor.fetchall()
        conn.close()
        return rows
    
    def delete_credential(self, label: str):
        """Delete credential from vault"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE label = ?", (label,))
        conn.commit()
        conn.close()
        print(f"✓ Credential '{label}' deleted!")

# ============================================================================
# VAULT MANAGER
# ============================================================================
class VaultManager:
    def __init__(self):
        self.db = VaultDatabase()
        self.crypto = CryptoManager()
        self.generator = PersonalPasswordGenerator()
        self.master_key = None
        self.authenticated = False
    
    def setup_master_password(self):
        """Create master password on first run"""
        print("\n🔐 FIRST TIME SETUP - Set Master Password")
        print("=" * 50)
        master_pwd = getpass("Create master password: ")
        confirm = getpass("Confirm password: ")
        
        if master_pwd != confirm:
            print("✗ Passwords don't match!")
            return False
        
        if len(master_pwd) < 12:
            print("✗ Master password must be at least 12 characters!")
            return False
        
        hash_value = self.crypto.hash_password(master_pwd)
        with open(MASTER_HASH_PATH, 'w') as f:
            f.write(hash_value)
        
        print("✓ Master password set successfully!")
        return True
    
    def authenticate(self) -> bool:
        """Authenticate with master password"""
        if not MASTER_HASH_PATH.exists():
            if not self.setup_master_password():
                return False
        
        master_pwd = getpass("\n🔓 Enter master password: ")
        
        with open(MASTER_HASH_PATH, 'r') as f:
            stored_hash = f.read()
        
        if not self.crypto.verify_password(master_pwd, stored_hash):
            print("✗ Incorrect password!")
            return False
        
        salt = b"replace_the_reused"  # Fixed salt for deterministic key
        self.master_key = self.crypto.derive_key(master_pwd, salt)
        self.authenticated = True
        print("✓ Authenticated!")
        return True
    
    def generate_and_save(self):
        """Generate password and offer to save"""
        print("\n📝 GENERATE PASSWORD")
        print("=" * 50)
        words_input = input("Enter personal words (comma-separated): ").strip()
        
        if not words_input:
            print("✗ Please enter at least one word!")
            return
        
        words = [w.strip() for w in words_input.split(",")]
        
        print("\nChoose length: [1] 12  [2] 14  [3] 16")
        choice = input("Select (1/2/3): ").strip()
        length_map = {"1": 12, "2": 14, "3": 16}
        
        if choice not in length_map:
            print("✗ Invalid choice!")
            return
        
        length = length_map[choice]
        password, strength = self.generator.generate_password(words, length)
        
        print(f"\n🔒 Generated Password: {password}")
        print(f"📊 Strength: {strength}")
        
        save = input("\n💾 Save to vault? (y/n): ").strip().lower()
        if save == 'y':
            label = input("Label (e.g., Gmail, Bank): ").strip()
            username = input("Username/Email: ").strip()
            url = input("URL (optional): ").strip() or None
            
            self.db.add_credential(label, username, password, url, self.master_key)
    
    def view_vault(self):
        """View all stored credentials"""
        print("\n📋 VAULT CONTENTS")
        print("=" * 50)
        
        credentials = self.db.list_credentials()
        if not credentials:
            print("✗ No credentials stored yet!")
            return
        
        for i, (label, url, created) in enumerate(credentials, 1):
            print(f"{i}. {label} | {url or 'N/A'} | Created: {created}")
        
        view_detail = input("\nView details? Enter label (or skip): ").strip()
        if view_detail:
            cred = self.db.get_credential(view_detail, self.master_key)
            if cred:
                print(f"\n  Label: {cred['label']}")
                print(f"  Username: {cred['username']}")
                print(f"  Password: {cred['password']}")
                print(f"  URL: {cred['url'] or 'N/A'}")
            else:
                print("✗ Credential not found!")
    
    def delete_vault_credential(self):
        """Delete credential from vault"""
        print("\n🗑️  DELETE CREDENTIAL")
        print("=" * 50)
        
        credentials = self.db.list_credentials()
        if not credentials:
            print("✗ No credentials to delete!")
            return
        
        for i, (label, _, _) in enumerate(credentials, 1):
            print(f"{i}. {label}")
        
        label = input("\nEnter label to delete: ").strip()
        confirm = input(f"Delete '{label}'? (y/n): ").strip().lower()
        
        if confirm == 'y':
            self.db.delete_credential(label)
    
    def run(self):
        """Main menu loop"""
        if not self.authenticate():
            return
        
        while True:
            print("\n" + "=" * 50)
            print("🔐 REPLACE THE REUSED - Password Manager")
            print("=" * 50)
            print("[1] Generate & Save Password")
            print("[2] View Vault")
            print("[3] Delete Credential")
            print("[4] Exit")
            print("=" * 50)
            
            choice = input("Select (1-4): ").strip()
            
            if choice == '1':
                self.generate_and_save()
            elif choice == '2':
                self.view_vault()
            elif choice == '3':
                self.delete_vault_credential()
            elif choice == '4':
                print("\n✨ Goodbye! Stay secure!\n")
                break
            else:
                print("✗ Invalid choice!")

# ============================================================================
# MAIN
# ============================================================================
if __name__ == "__main__":
    vault = VaultManager()
    vault.run()
