import json
import os
from datetime import datetime
from urllib.parse import urlparse

from utils.colors import Colors
from reporting.models import Finding, ScoreResult
from reporting.html_report import render_html_report
from core.config import ScanConfig


class Reporter:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.findings: list[Finding] = []
        self.score: ScoreResult | None = None

        # Dedup key set
        self._seen = set()

        os.makedirs(self.config.out_dir, exist_ok=True)

        domain = urlparse(config.target).netloc.replace(":", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_name = f"scan_{domain}_{ts}"
        self.txt_path = os.path.join(self.config.out_dir, f"{self.base_name}.txt")
        self.json_path = os.path.join(self.config.out_dir, f"{self.base_name}.json")
        self.html_path = os.path.join(self.config.out_dir, f"{self.base_name}.html")

    def _key(self, finding: Finding) -> str:
        host = urlparse(finding.url).netloc
        return f"{finding.title}|{finding.severity}|{finding.category}|{host}"

    def add(self, finding: Finding):
        k = self._key(finding)
        if k in self._seen:
            return
        self._seen.add(k)

        self.findings.append(finding)
        print(f"{Colors.FINDING} {finding.severity} | {finding.category} | {finding.title} | {finding.url}")

    def set_score(self, score: ScoreResult):
        self.score = score

    def save(self):
        fmt = self.config.output_format

        if fmt in ("txt", "both"):
            self._save_txt()
        if fmt in ("json", "both"):
            self._save_json()
        if fmt in ("html", "both"):
            self._save_html()

        print(f"{Colors.SUCCESS} Reports saved under: {self.config.out_dir}")

    def _save_txt(self):
        with open(self.txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 70 + "\n")
            f.write(" CoreInspect Security Audit Report\n")
            f.write(f" Target: {self.config.target}\n")
            f.write(f" Profile: {self.config.profile}\n")
            f.write(f" Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")

            if self.score:
                f.write(f"Security Score: {self.score.score}/100  Grade: {self.score.grade}\n")
                f.write(f"Deductions: {self.score.deductions}\n")
                f.write("Breakdown:\n")
                for k, v in self.score.breakdown.items():
                    f.write(f"  - {k}: {v}\n")
                f.write("\nTop issues:\n")
                for i, issue in enumerate(self.score.top_issues, 1):
                    f.write(f"  {i}. [{issue.get('severity')}] {issue.get('title')} ({issue.get('url')})\n")
                f.write("\n" + "-" * 70 + "\n\n")

            if not self.findings:
                f.write("No findings.\n")
                return

            for idx, finding in enumerate(self.findings, 1):
                f.write(f"[{idx}] {finding.title}\n")
                f.write(f"    Severity: {finding.severity}\n")
                f.write(f"    Category: {finding.category}\n")
                f.write(f"    URL: {finding.url}\n")
                if finding.evidence:
                    f.write(f"    Evidence: {finding.evidence}\n")
                if finding.recommendation:
                    f.write(f"    Recommendation: {finding.recommendation}\n")
                f.write("-" * 70 + "\n")

        print(f"{Colors.SUCCESS} TXT report: {self.txt_path}")

    def _save_json(self):
        payload = {
            "target": self.config.target,
            "profile": self.config.profile,
            "timestamp": datetime.now().isoformat(),
            "score": (self.score.__dict__ if self.score else None),
            "findings": [f.to_dict() for f in self.findings],
        }
        with open(self.json_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"{Colors.SUCCESS} JSON report: {self.json_path}")

    def _save_html(self):
        html = render_html_report(
            target=self.config.target,
            profile=self.config.profile,
            score_result=self.score,
            findings=self.findings,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        with open(self.html_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"{Colors.SUCCESS} HTML report: {self.html_path}")
