# Replace the Reused 🔐

A secure password generator + encrypted vault manager. Generate strong, memorable passwords from your personal words and store them in a military-grade encrypted vault.

## Features

- 🎯 **Personal Password Generator** - Create strong passwords from your meaningful words
- 🔒 **Military-Grade Encryption** - ChaCha20Poly1305 authenticated encryption
- 🗄️ **Encrypted Vault** - Store credentials locally with master password protection
- 🔑 **Argon2 Hashing** - Modern, brute-force resistant key derivation
- 💾 **Local Storage** - Nothing stored online, full privacy

## 🚀 Quick Start

### Installation
```bash
# Clone the repo
git clone https://github.com/SarahModi/replace-the-reused.git
cd replace-the-reused

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Usage
```bash
python3 main.py
```

**First Run:**
- Set your master password (12+ characters)
- This unlocks your vault

**Main Menu:**
1. **Generate & Save Password** - Enter personal words → Get strong password → Save to vault
2. **View Vault** - See all stored credentials
3. **Delete Credential** - Remove entries
4. **Exit**

## 🔐 Security

- **Encryption:** ChaCha20Poly1305 (authenticated)
- **Key Derivation:** PBKDF2 (100,000 iterations)
- **Master Password:** Argon2 hashing
- **Storage:** SQLite with encrypted blobs
- **Privacy:** Everything stored locally (~/.replace_the_reused/)

## 📖 How It Works

1. **Generate** - Enter meaningful words (e.g., "blue, 2008, kitten")
2. **Get Strong Password** - Algorithm creates 12/14/16 char passwords
3. **Save to Vault** - Master password encrypts and stores it
4. **Retrieve Anytime** - Authenticate → View/use saved passwords


## 🌐 Live Demo

Frontend: https://YOUR_GITHUB_USERNAME.github.io/replace-the-reused
Backend API: https://replace-the-reused-api.onrender.com

## 🚀 Deployment

### Frontend (GitHub Pages)
1. Push to `main` branch
2. GitHub Actions auto-builds and deploys
3. Live at: https://YOUR_GITHUB_USERNAME.github.io/replace-the-reused

### Backend (Render)
See below...

## 🛡️ Best Practices

- Use a strong, unique master password (16+ characters)
- Don't reuse your master password elsewhere
- Backup your vault file (~/.replace_the_reused/vault.db)
- Never share your master password

## 🤝 Contributing

Found a bug? Have ideas? Open an issue or submit a PR!

## 📜 License

MIT License - Feel free to use, modify, and distribute

---

Made with ❤️ for better cybersecurity habits
```

### **4. `.gitignore`** (don't upload sensitive files)
```
# Virtual environment
venv/
env/
__pycache__/
*.pyc

# Vault files (NEVER commit)
.replace_the_reused/
vault.db
.master_hash

# IDE
.vscode/
.idea/
*.swp

# OS
.DS_Store
```

### **5. `LICENSE`** 
Just add MIT License - GitHub will provide a template when you add a file

---

## Steps to Add Files via Browser:

1. **Go to your repo** on GitHub
2. **Click "Add file" → "Create new file"**
3. **Name the file** (e.g., `main.py`)
4. **Paste the code** into the editor
5. **Click "Commit new file"**
6. **Repeat for each file**

**Order to add:**
1. `main.py` (your app)
2. `requirements.txt` (dependencies)
3. `README.md` (documentation)
4. `.gitignore` (security)

## ✅ Final Repo Structure:

replace-the-reused/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
```
