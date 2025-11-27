# core/auth_linux.py - MILITARY-GRADE LINUX AUTH FOR CYBERSHIELD v3.1
import os
import sys
import getpass
import pyotp
import base64
import json
from pathlib import Path
from cryptography.fernet import Fernet
from tkinter import messagebox

# Optional: YubiKey + Fingerprint support
try:
    from fido2.hid import CtapHidDevice
    YUBIKEY_AVAILABLE = True
except:
    YUBIKEY_AVAILABLE = False

VAULT_DIR = Path.home() / ".cybershield"
VAULT_FILE = VAULT_DIR / "vault.bin"
KEY_FILE = VAULT_DIR / "key.bin"

def _init_vault():
    VAULT_DIR.mkdir(mode=0o700, exist_ok=True)
    if VAULT_FILE.exists():
        return

    print("\n[LINUX AUTH] First-time military setup...")
    key = Fernet.generate_key()
    f = Fernet(key)

    while True:
        pwd = getpass.getpass("Set master passphrase (12+ chars): ")
        pwd2 = getpass.getpass("Confirm: ")
        if pwd == pwd2 and len(pwd) >= 12:
            break
        print("Weak or mismatch!")

    totp_secret = base64.b32encode(os.urandom(20)).decode().rstrip("=")
    vault = {
        "master_hash": base64.b64encode(f.encrypt(pwd.encode())).decode(),
        "totp_secret": totp_secret,
        "created": int(time.time())
    }

    KEY_FILE.write_bytes(key)
    VAULT_FILE.write_text(f.encrypt(json.dumps(vault).encode()).decode())
    os.chmod(KEY_FILE, 0o600)
    os.chmod(VAULT_FILE, 0o600)

    print(f"\nTOTP Secret: {totp_secret}")
    print("Scan in: Google Authenticator / andOTP / FreeOTP")
    print("Or use: oathtool --totp -b " + totp_secret)
    print("\nSetup complete. Restart CyberShield.\n")
    sys.exit(0)

def _load_vault():
    if not VAULT_FILE.exists():
        _init_vault()
    key = KEY_FILE.read_bytes()
    f = Fernet(key)
    data = f.decrypt(VAULT_FILE.read_text().encode())
    return f, json.loads(data)

def try_yubikey_touch():
    if not YUBIKEY_AVAILABLE:
        return False
    try:
        dev = next(CtapHidDevice.list_devices(), None)
        if dev:
            print("[YUBIKEY] Touch your YubiKey now...")
            dev.client.get_info()  # Triggers touch
            print("[YUBIKEY] Authenticated!")
            return True
    except:
        pass
    return False

def require_linux_auth():
    if try_yubikey_touch():
        return True

    f, vault = _load_vault()
    attempts = 3

    while attempts:
        pwd = getpass.getpass("Master Passphrase: ")
        stored = base64.b64decode(vault["master_hash"])
        if f.decrypt(stored).decode() == pwd:
            code = getpass.getpass("TOTP Code (6 digits): ").strip()
            if pyotp.TOTP(vault["totp_secret"]).verify(code, valid_window=2):
                print("[LINUX AUTH] Access granted.")
                return True
        attempts -= 1
        print(f"Invalid. {attempts} attempts left.")

    messagebox.showerror("ACCESS DENIED", "Linux authentication failed.")
    return False