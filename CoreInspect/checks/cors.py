from checks.base import BaseCheck
from reporting.models import Finding


class CORSCheck(BaseCheck):
    name = "CORSCheck"

    def run_url(self, url: str):
        r = self.req.get(url)
        if not r:
            return

        aco = r.headers.get("Access-Control-Allow-Origin")
        acc = r.headers.get("Access-Control-Allow-Credentials")

        if not aco:
            return

        # Heuristics:
        if aco.strip() == "*" and (acc or "").lower().strip() == "true":
            self.reporter.add(Finding(
                title="Potentially unsafe CORS: wildcard origin with credentials",
                severity="High",
                category="CORS",
                url=url,
                evidence=f"ACAO={aco}, ACAC={acc}",
                recommendation="Do not use '*' with credentials; reflect only trusted origins and validate them server-side.",
            ))
        elif aco.strip() == "*":
            self.reporter.add(Finding(
                title="CORS allows any origin (wildcard)",
                severity="Medium",
                category="CORS",
                url=url,
                evidence=f"ACAO={aco}",
                recommendation="Restrict Access-Control-Allow-Origin to trusted origins if sensitive data is exposed.",
            ))