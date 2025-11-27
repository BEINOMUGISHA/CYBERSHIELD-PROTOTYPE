# scanners/crawler.py - CyberShield Pro Crawler v2.0
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import re

class SmartCrawler:
    def __init__(self, user_agent="CyberShield/2.0 (+https://github.com/yourname/cybershield)"):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        })
        self.visited = set()
        self.to_visit = set()
        self.found_urls = []
        self.lock = threading.Lock()
        self.domain = None
        self.max_pages = 100
        self.max_depth = 5
        self.follow_js_links = True  # Extract from <a>, <form>, onclick, etc.

    def is_valid_url(self, url):
        """Filter out unwanted URLs"""
        parsed = urlparse(url)
        if not parsed.scheme in ["http", "https"]:
            return False
        if parsed.netloc != self.domain:
            return False
        if any(ext in parsed.path.lower() for ext in [".pdf", ".jpg", ".png", ".gif", ".zip", ".exe", ".js", ".css"]):
            return False
        if "logout" in url.lower() or "signout" in url.lower():
            return False
        return True

    def extract_links(self, url, html):
        """Extract ALL possible links (a, form, js events, meta refresh, etc.)"""
        links = set()
        soup = BeautifulSoup(html, "lxml")

        # Standard <a href>
        for a in soup.find_all("a", href=True):
            links.add(urljoin(url, a["href"]))

        # Forms (action + hidden inputs)
        for form in soup.find_all("form", action=True):
            action = urljoin(url, form.get("action", ""))
            if action:
                links.add(action)

        # JavaScript links: onclick="window.location='...'", window.open, etc.
        if self.follow_js_links:
            js_patterns = [
                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                r'window\.open\s*\(\s*["\']([^"\']+)["\']',
                r'href\s*=\s*["\']([^"\']*\.html?[^"\']*)["\']',
                r'src\s*=\s*["\']([^"\']+\.html?[^"\']*)["\']',
            ]
            for pattern in js_patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    full = urljoin(url, match.split("'")[0].split('"')[0])
                    links.add(full)

        # Meta refresh
        meta = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
        if meta and "url=" in meta.get("content", "").lower():
            redirect = meta["content"].split("url=")[-1].strip()
            links.add(urljoin(url, redirect))

        return links

    def crawl_page(self, url, depth=0):
        if depth > self.max_depth:
            return

        with self.lock:
            if url in self.visited or url in self.to_visit:
                return
            self.to_visit.add(url)

        try:
            response = self.session.get(url, timeout=10, allow_redirects=True, verify=False)
            if response.status_code != 200:
                return
            if not response.headers.get("content-type", "").startswith("text/html"):
                return

            with self.lock:
                self.visited.add(url)
                self.to_visit.discard(url)
                if len(self.found_urls) < self.max_pages:
                    self.found_urls.append(url)

            # Extract and queue new links
            try:
                new_links = self.extract_links(url, response.text)
                valid_links = {link for link in new_links if self.is_valid_url(link)}
                
                with self.lock:
                    for link in valid_links:
                        if link not in self.visited and link not in self.to_visit and len(self.found_urls) < self.max_pages:
                            self.to_visit.add(link)

            except: pass

        except Exception as e:
            pass

    def crawl(self, start_url, max_pages=100, max_depth=5, max_workers=15):
        """
        Main crawl function - fast, smart, and respectful
        """
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.domain = urlparse(start_url).netloc
        self.to_visit.add(start_url)

        print(f"[+] Starting smart crawl on {start_url}")
        print(f"    → Max {max_pages} pages, depth {max_depth}, {max_workers} threads")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            while self.to_visit and len(self.found_urls) < max_pages:
                current_batch = list(self.to_visit)[:max_workers * 2]
                futures = [
                    executor.submit(self.crawl_page, url, depth=0)
                    for url in current_batch
                ]
                # Small delay to be respectful
                time.sleep(0.3)

        print(f"[+] Crawling complete! Found {len(self.found_urls)} unique pages.")
        return sorted(self.found_urls)

# Easy-to-use function (keep backward compatibility)
def crawl(start_url, max_pages=100):
    crawler = SmartCrawler()
    return crawler.crawl(start_url, max_pages=max_pages, max_depth=5, max_workers=20)