from checks.base import BaseCheck
from reporting.models import Finding


class FormsCheck(BaseCheck):
    name = "FormsCheck"

    def run_url(self, url: str):
        # URL-level not needed; forms come from crawler
        return

    def run_form(self, form: dict):
        action = form.get("action", "")
        method = (form.get("method") or "get").lower()
        inputs = form.get("inputs") or []
        page_url = form.get("url") or action

        # Heuristics: CSRF token presence (name contains token/csrf)
        has_csrf = any(("csrf" in (i.get("name") or "").lower()) or ("token" in (i.get("name") or "").lower()) for i in inputs)

        if method == "post" and not has_csrf:
            self.reporter.add(Finding(
                title="POST form without obvious CSRF token (heuristic)",
                severity="Medium",
                category="Forms",
                url=page_url,
                evidence=f"Form action={action}",
                recommendation="Implement CSRF protection (synchronizer token / double submit cookie) for state-changing requests.",
                extra={"form": form},
            ))

        # Password field hygiene
        has_password = any((i.get("type") or "").lower() == "password" for i in inputs)
        if has_password and not action.startswith("https://"):
            self.reporter.add(Finding(
                title="Password form action is not HTTPS",
                severity="High",
                category="Forms",
                url=page_url,
                evidence=f"Form action={action}",
                recommendation="Ensure credentials are submitted only over HTTPS.",
                extra={"form": form},
            ))