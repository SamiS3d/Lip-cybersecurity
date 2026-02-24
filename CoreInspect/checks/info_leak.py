from checks.base import BaseCheck
from reporting.models import Finding


class InfoLeakCheck(BaseCheck):
    name = "InfoLeakCheck"

    def run_url(self, url: str):
        r = self.req.get(url)
        if not r:
            return

        server = r.headers.get("Server", "")
        x_powered = r.headers.get("X-Powered-By", "")

        if server:
            self.reporter.add(Finding(
                title="Server header disclosed",
                severity="Info",
                category="InfoLeak",
                url=url,
                evidence=f"Server: {server}",
                recommendation="Consider minimizing server banner information if not needed.",
            ))

        if x_powered:
            self.reporter.add(Finding(
                title="X-Powered-By header disclosed",
                severity="Info",
                category="InfoLeak",
                url=url,
                evidence=f"X-Powered-By: {x_powered}",
                recommendation="Disable X-Powered-By to reduce technology fingerprinting.",
            ))