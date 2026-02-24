from bs4 import BeautifulSoup
from checks.base import BaseCheck
from reporting.models import Finding


class MixedContentCheck(BaseCheck):
    name = "MixedContentCheck"

    def run_url(self, url: str):
        if not url.startswith("https://"):
            return

        r = self.req.get(url)
        if not r or not r.text:
            return

        html = r.text
        if "<html" not in html.lower():
            return

        soup = BeautifulSoup(html, "lxml")
        http_resources = []

        # src/href attributes that can load mixed content
        for tag in soup.find_all(src=True):
            src = (tag.get("src") or "").strip()
            if src.startswith("http://"):
                http_resources.append(src)

        for tag in soup.find_all(href=True):
            href = (tag.get("href") or "").strip()
            # stylesheets or other resources
            if href.startswith("http://"):
                http_resources.append(href)

        if http_resources:
            sample = http_resources[:5]
            self.reporter.add(Finding(
                title="Mixed content detected (HTTP resources on HTTPS page)",
                severity="Medium",
                category="Headers",
                url=url,
                evidence="Examples: " + ", ".join(sample),
                recommendation="Serve all subresources over HTTPS to avoid downgrade and MITM risks.",
                extra={"count": len(http_resources)},
            ))
