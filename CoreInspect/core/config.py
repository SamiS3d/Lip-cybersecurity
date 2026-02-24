from dataclasses import dataclass


@dataclass(frozen=True)
class ScanConfig:
    target: str
    profile: str = "passive"          # passive | active | deep
    max_pages: int = 25
    timeout: int = 12
    concurrency: int = 4
    rate_limit_rps: float = 2.0
    headless: bool = True
    out_dir: str = "reports"
    output_format: str = "both"       # txt | json | html | both
    authorized: bool = False
