from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List


@dataclass
class Finding:
    title: str
    severity: str              # Critical/High/Medium/Low/Info
    category: str              # Headers/Cookies/TLS/CORS/Exposure/Forms/Input/InfoLeak
    url: str
    evidence: str = ""
    recommendation: str = ""
    extra: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d["extra"] is None:
            d["extra"] = {}
        return d


@dataclass
class ScoreResult:
    score: int
    grade: str
    deductions: int
    breakdown: Dict[str, int]
    top_issues: List[Dict[str, Any]]