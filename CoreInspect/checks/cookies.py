from checks.base import BaseCheck
from reporting.models import Finding


class CookiesCheck(BaseCheck):
    name = "CookiesCheck"

    def run_url(self, url: str):
        r = self.req.get(url)
        if not r:
            return

        set_cookie = r.headers.get("Set-Cookie")
        if not set_cookie:
            return

        # If multiple cookies, requests may fold; handle as string heuristics
        sc = set_cookie.lower()

        if "secure" not in sc and url.startswith("https://"):
            self.reporter.add(Finding(
                title="Cookie without Secure flag detected",
                severity="Medium",
                category="Cookies",
                url=url,
                evidence=f"Set-Cookie: {set_cookie}",
                recommendation="Set Secure on session cookies to prevent leakage over HTTP.",
            ))
        if "httponly" not in sc:
            self.reporter.add(Finding(
                title="Cookie without HttpOnly flag detected",
                severity="Medium",
                category="Cookies",
                url=url,
                evidence=f"Set-Cookie: {set_cookie}",
                recommendation="Set HttpOnly on session cookies to reduce XSS cookie theft.",
            ))
        if "samesite" not in sc:
            self.reporter.add(Finding(
                title="Cookie without SameSite attribute detected",
                severity="Low",
                category="Cookies",
                url=url,
                evidence=f"Set-Cookie: {set_cookie}",
                recommendation="Set SameSite=Lax/Strict (or None;Secure when needed) to reduce CSRF risk.",
            ))