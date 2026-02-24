import time
import threading
from typing import Optional, Dict, Any

import requests
from urllib3.exceptions import InsecureRequestWarning
import urllib3

urllib3.disable_warnings(InsecureRequestWarning)


class RateLimiter:
    """
    Simple, thread-safe token-ish limiter: ensures at least (1/rps) seconds between requests.
    """
    def __init__(self, rps: float):
        self.min_interval = 0 if not rps or rps <= 0 else (1.0 / float(rps))
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self.min_interval - (now - self._last)
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._last = time.monotonic()


class Requester:
    def __init__(self, timeout: int = 12, rate_limit_rps: float = 2.0):
        self.session = requests.Session()
        self.timeout = timeout
        self.limiter = RateLimiter(rate_limit_rps)

        self.session.headers.update({
            "User-Agent": "CoreInspect/2.0 (+security-auditor)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        })

    def get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Optional[requests.Response]:
        self.limiter.wait()
        try:
            return self.session.get(url, params=params, timeout=self.timeout, verify=False, allow_redirects=True)
        except requests.exceptions.RequestException:
            return None

    def head(self, url: str) -> Optional[requests.Response]:
        self.limiter.wait()
        try:
            return self.session.head(url, timeout=self.timeout, verify=False, allow_redirects=True)
        except requests.exceptions.RequestException:
            return None

    def post(self, url: str, data: Optional[Dict[str, Any]] = None) -> Optional[requests.Response]:
        self.limiter.wait()
        try:
            return self.session.post(url, data=data, timeout=self.timeout, verify=False, allow_redirects=True)
        except requests.exceptions.RequestException:
            return None