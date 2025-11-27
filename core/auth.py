# core/auth.py - CyberShield MFA Authentication System
import os
import json
import time
import base64
from cryptography.fernet import Fernet
from pyotp import TOTP
from pathlib import Path

AUTH_FILE = Path("core/.auth_data")
KEY_FILE = Path("core/.auth_key")

def _get_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()
    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    os.chmod(KEY_FILE, 0o600)
    return key

fernet = Fernet(_get_key())

def init_auth():
    """First-time setup — run once"""
    if AUTH_FILE.exists():
        return
    
    print("[AUTH] First-time setup — creating admin account")
    username = input("Username (default: admin): ").strip() or "admin"
    password = input("Password: ")
    
    totp = TOTP(base64.b32encode(os.urandom(20)).decode().rstrip("="))
    secret = totp.secret
    
    data = {
        "username": username,
        "password_hash": base64.b64encode(fernet.encrypt(password.encode())).decode(),
        "totp_secret": secret,
        "failed_attempts": 0,
        "last_login": 0,
        "locked_until": 0
    }
    
    AUTH_FILE.parent.mkdir(exist_ok=True)
    AUTH_FILE.write_text(fernet.encrypt(json.dumps(data).encode()).decode())
    os.chmod(AUTH_FILE, 0o600)
    
    print(f"\n[AUTH] Account created!")
    print(f"   Username: {username}")
    print(f"   TOTP Secret: {secret}")
    print(f"   → Scan this QR in Google Authenticator:")
    print(totp.provisioning_uri(name=username, issuer_name="CyberShield"))
    print("\n   Save this secret! You won't see it again.\n")

def authenticate(username: str, password: str, totp_code: str = None) -> bool:
    if not AUTH_FILE.exists():
        return False
    
    try:
        data = json.loads(fernet.decrypt(AUTH_FILE.read_text().encode()))
    except:
        return False
    
    now = time.time()
    
    # Lockout check
    if data.get("locked_until", 0) > now:
        return False
    
    # Username check
    if data["username"] != username:
        return False
    
    # Password check
    try:
        stored = base64.b64decode(data["password_hash"])
        if fernet.decrypt(stored).decode() != password:
            data["failed_attempts"] += 1
            if data["failed_attempts"] >= 5:
                data["locked_until"] = now + 300  # 5 min lock
            _save(data)
            return False
    except:
        return False
    
    # TOTP check
    if totp_code:
        totp = TOTP(data["totp_secret"])
        if not totp.verify(totp_code, valid_window=1):
            return False
    
    # Success
    data["failed_attempts"] = 0
    data["last_login"] = now
    _save(data)
    return True

def _save(data):
    AUTH_FILE.write_text(fernet.encrypt(json.dumps(data).encode()).decode())

def is_authenticated():
    data = json.loads(fernet.decrypt(AUTH_FILE.read_text().encode()))
    return time.time() - data.get("last_login", 0) < 900  # 15 min session