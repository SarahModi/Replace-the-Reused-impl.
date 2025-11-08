from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_session import Session
import os
import hashlib
import secrets
import string
import sqlite3
from pathlib import Path
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import base64
from functools import wraps
from datetime import datetime

app = Flask(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

Session(app)
CORS(app)

# Paths
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
            return True, "Credential saved!"
        except sqlite3.IntegrityError:
            return False, f"Label '{label}' already exists!"
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
            "id": row[0],
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
        cursor.execute("SELECT id, label, url, created_at FROM credentials")
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                "id": row[0],
                "label": row[1],
                "url": row[2],
                "created_at": row[3]
            }
            for row in rows
        ]
    
    def delete_credential(self, label: str) -> bool:
        """Delete credential from vault"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE label = ?", (label,))
        conn.commit()
        conn.close()
        return True

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================
def login_required(f):
    """Decorator to check if user is authenticated"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'authenticated' not in session or not session['authenticated']:
            return jsonify({"error": "Not authenticated"}), 401
        return f(*args, **kwargs)
    return decorated_function

# Initialize instances
db = VaultDatabase()
crypto = CryptoManager()
generator = PersonalPasswordGenerator()

# ============================================================================
# ROUTES - AUTHENTICATION
# ============================================================================
@app.route('/api/setup', methods=['POST'])
def setup():
    """Setup master password (first run)"""
    data = request.json
    master_password = data.get('masterPassword', '').strip()
    
    if len(master_password) < 12:
        return jsonify({"error": "Master password must be at least 12 characters"}), 400
    
    if MASTER_HASH_PATH.exists():
        return jsonify({"error": "Vault already initialized"}), 400
    
    hash_value = crypto.hash_password(master_password)
    with open(MASTER_HASH_PATH, 'w') as f:
        f.write(hash_value)
    
    return jsonify({"message": "Master password set successfully"}), 201

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate with master password"""
    data = request.json
    master_password = data.get('masterPassword', '')
    
    if not master_password:
        return jsonify({"error": "Master password required"}), 400
    
    # Check if vault is initialized
    if not MASTER_HASH_PATH.exists():
        # First time - setup
        return setup()
    
    # Verify password
    with open(MASTER_HASH_PATH, 'r') as f:
        stored_hash = f.read()
    
    if not crypto.verify_password(master_password, stored_hash):
        return jsonify({"error": "Incorrect master password"}), 401
    
    # Create session
    salt = b"replace_the_reused"
    master_key = crypto.derive_key(master_password, salt)
    
    session['authenticated'] = True
    session['master_key'] = base64.b64encode(master_key).decode()
    session.permanent = True
    
    return jsonify({"message": "Authenticated successfully"}), 200

@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout and clear session"""
    session.clear()
    return jsonify({"message": "Logged out"}), 200

# ============================================================================
# ROUTES - PASSWORD GENERATOR
# ============================================================================
@app.route('/api/generate', methods=['POST'])
@login_required
def generate():
    """Generate password from personal words"""
    data = request.json
    words = data.get('words', [])
    length = data.get('length', 16)
    
    if not words or all(not w.strip() for w in words):
        return jsonify({"error": "Please provide personal words"}), 400
    
    try:
        password, strength = generator.generate_password(words, length)
        return jsonify({
            "password": password,
            "strength": strength,
            "length": length
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

# ============================================================================
# ROUTES - VAULT OPERATIONS
# ============================================================================
@app.route('/api/vault/add', methods=['POST'])
@login_required
def add_credential():
    """Save credential to vault"""
    data = request.json
    label = data.get('label', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    url = data.get('url', '').strip() or None
    
    if not label or not username or not password:
        return jsonify({"error": "Label, username, and password are required"}), 400
    
    # Get master key from session
    master_key = base64.b64decode(session.get('master_key', ''))
    
    success, message = db.add_credential(label, username, password, url, master_key)
    
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 400

@app.route('/api/vault/list', methods=['GET'])
@login_required
def list_vault():
    """List all credentials"""
    credentials = db.list_credentials()
    return jsonify({"credentials": credentials}), 200

@app.route('/api/vault/get/<label>', methods=['GET'])
@login_required
def get_vault_credential(label):
    """Get specific credential details"""
    master_key = base64.b64decode(session.get('master_key', ''))
    
    credential = db.get_credential(label, master_key)
    
    if not credential:
        return jsonify({"error": "Credential not found"}), 404
    
    return jsonify(credential), 200

@app.route('/api/vault/delete/<label>', methods=['DELETE'])
@login_required
def delete_vault_credential(label):
    """Delete credential from vault"""
    db.delete_credential(label)
    return jsonify({"message": f"Credential '{label}' deleted"}), 200

# ============================================================================
# ERROR HANDLERS
# ============================================================================
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Internal server error"}), 500

# ============================================================================
# HEALTH CHECK
# ============================================================================
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"}), 200

# ============================================================================
# MAIN
# ============================================================================
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug, host='0.0.0.0', port=port)
