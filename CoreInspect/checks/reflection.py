from checks.base import BaseCheck
from reporting.models import Finding


class ReflectionCheck(BaseCheck):
    """
    Non-destructive reflection check:
    - Sends a benign marker value in query/form fields.
    - If marker is reflected in HTML response, flag as 'potential reflected injection surface'.
    It does NOT attempt to execute scripts or break syntax intentionally.
    """
    name = "ReflectionCheck"
    MARKER = "COREINSPECT_REFLECT_9f3a2"

    def run_url(self, url: str):
        if "?" not in url:
            return

        base, qs = url.split("?", 1)
        parts = qs.split("&")

        for i in range(len(parts)):
            if "=" not in parts[i]:
                continue
            k = parts[i].split("=", 1)[0]
            test_parts = parts.copy()
            test_parts[i] = f"{k}={self.MARKER}"
            test_url = f"{base}?{'&'.join(test_parts)}"

            r = self.req.get(test_url)
            if r and self.MARKER in (r.text or ""):
                self.reporter.add(Finding(
                    title="Reflected input detected in response (benign marker)",
                    severity="Medium",
                    category="Input",
                    url=test_url,
                    evidence=f"Marker '{self.MARKER}' reflected in HTML response.",
                    recommendation="Apply proper output encoding and input validation; review endpoints reflecting user input.",
                ))
                return

    def run_form(self, form: dict):
        action = form.get("action")
        method = (form.get("method") or "get").lower()
        inputs = form.get("inputs") or []
        page_url = form.get("url") or action

        data = {}
        for i in inputs:
            name = i.get("name")
            if name:
                data[name] = self.MARKER

        if not data or not action:
            return

        if method == "post":
            r = self.req.post(action, data=data)
        else:
            r = self.req.get(action, params=data)

        if r and self.MARKER in (r.text or ""):
            self.reporter.add(Finding(
                title="Reflected form input detected (benign marker)",
                severity="Medium",
                category="Input",
                url=page_url,
                evidence=f"Marker '{self.MARKER}' reflected after submitting form to {action}.",
                recommendation="Apply output encoding; validate/normalize inputs; consider templating auto-escaping.",
                extra={"form": form},
            ))