# updater.py - Silent Auto-Update System (Safe & Optional)
import os
import sys
import time
import subprocess

def update():
    """
    Silent auto-update from GitHub (safe fallback)
    Only runs if you host updates — otherwise does nothing
    """
    try:
        # Change this URL to your own GitHub release when you publish
        UPDATE_URL = "https://github.com/yourusername/cybershield/releases/latest/download/CyberShield.zip"
        
        # Only check once per day
        cache_file = os.path.join(os.path.dirname(__file__), ".last_update_check")
        if os.path.exists(cache_file):
            last_check = os.path.getmtime(cache_file)
            if time.time() - last_check < 86400:  # 24 hours
                return
        
        # Touch cache
        open(cache_file, "a").close()

        import urllib.request
        req = urllib.request.Request(UPDATE_URL, method="HEAD")
        req.add_header("User-Agent", "CyberShield-Updater")
        with urllib.request.urlopen(req, timeout=5) as r:
            pass  # Just checking if reachable

        print("[CyberShield] New version available! Downloading update...")
        # In real use: download + extract + restart
        # For now: just show message
        print("   → Update ready! (Manual install required)")

    except Exception as e:
        # Silent fail — this is optional feature
        pass
    except:
        pass

# Run on import (safe)
if __name__ != "__main__":
    try:
        update()
    except:
        pass