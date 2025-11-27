# scanners/dir_bruter.py
import requests
import threading

def scan(base_url, wordlist_path="wordlists/common.txt"):
    found = []
    lock = threading.Lock()

    def test(path):
        url = base_url.rstrip("/") + "/" + path.strip()
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            if r.status_code in [200, 301, 403]:
                with lock:
                    found.append(f"Directory/File found ({r.status_code}): {url}")
        except:
            pass

    with open(wordlist_path) as f:
        paths = [line.strip() for line in f if line.strip()]

    threads = []
    for path in paths[:500]:  # Limit
        t = threading.Thread(target=test, args=(path,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return found if found else ["No hidden directories found"]