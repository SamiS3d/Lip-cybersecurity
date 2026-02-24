from collections import defaultdict
from reporting.models import ScoreResult


class Scorer:
    # Deduction weights by severity
    SEV_WEIGHT = {
        "Critical": 15,
        "High": 10,
        "Medium": 5,
        "Low": 2,
        "Info": 0,
    }

    # Category caps to avoid score being destroyed by repeated same category findings
    CATEGORY_CAP = {
        "TLS": 25,
        "Headers": 25,
        "Cookies": 20,
        "CORS": 15,
        "Exposure": 20,
        "Forms": 15,
        "Input": 15,
        "InfoLeak": 10,
        "Other": 10,
    }

    def compute(self, findings, target: str) -> ScoreResult:
        by_cat = defaultdict(int)

        for f in findings:
            cat = f.category if f.category in self.CATEGORY_CAP else "Other"
            by_cat[cat] += self.SEV_WEIGHT.get(f.severity, 0)

        # Apply caps per category
        capped = {cat: min(points, self.CATEGORY_CAP[cat]) for cat, points in by_cat.items()}
        deductions = sum(capped.values())

        score = max(0, 100 - deductions)
        grade = self._grade(score)

        # Top issues: prioritize severity weight then uniqueness
        sorted_findings = sorted(
            findings,
            key=lambda x: (self.SEV_WEIGHT.get(x.severity, 0), x.category),
            reverse=True,
        )
        top = [{"title": f.title, "severity": f.severity, "category": f.category, "url": f.url} for f in sorted_findings[:8]]

        breakdown = dict(sorted(capped.items(), key=lambda kv: kv[0]))
        return ScoreResult(score=score, grade=grade, deductions=deductions, breakdown=breakdown, top_issues=top)

    def _grade(self, score: int) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 50:
            return "D"
        return "F"