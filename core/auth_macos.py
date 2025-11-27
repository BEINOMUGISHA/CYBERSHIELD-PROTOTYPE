# core/auth_macos.py - MILITARY-GRADE MACOS AUTH (Touch ID / Face ID)
import os
import sys
from tkinter import messagebox

# === PYOBJC IMPORTS (only work after `pip install pyobjc`) ===
try:
    import objc
    from Foundation import NSBundle
    from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthenticationWithBiometrics
    MACOS_AUTH_AVAILABLE = True
except ImportError as e:
    print("[macOS AUTH] pyobjc not installed → pip install pyobjc")
    MACOS_AUTH_AVAILABLE = False

# === Fallback: Simple passphrase (if pyobjc missing) ===
def _fallback_passphrase():
    from getpass import getpass
    correct = "cyberelite2025"  # Change this or load from encrypted file
    attempt = getpass("Enter master passphrase: ")
    if attempt == correct:
        print("[macOS] Passphrase accepted (fallback)")
        return True
    messagebox.showerror("Access Denied", "Wrong passphrase.")
    return False

# === MAIN AUTH FUNCTION ===
def require_macos_auth():
    if not MACOS_AUTH_AVAILABLE:
        print("[macOS] pyobjc missing → using passphrase fallback")
        return _fallback_passphrase()

    try:
        context = LAContext.new()
        policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics  # Touch ID / Face ID
        reason = "CyberShield UNSTOPPABLE Access"

        success, error = context.evaluatePolicy_localizedReason_reply_(
            policy, reason, None
        )

        if success:
            print("[macOS] Touch ID / Face ID authenticated!")
            return True
        else:
            print(f"[macOS] Biometric failed: {error.localizedDescription()}")
            return _fallback_passphrase()

    except Exception as e:
        print(f"[macOS] Auth error: {e}")
        return _fallback_passphrase()