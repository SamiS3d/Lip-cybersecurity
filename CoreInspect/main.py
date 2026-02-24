import argparse
import sys
from urllib.parse import urlparse

from core.logging_config import setup_logging, get_logger
from core.config import ScanConfig
from core.requester import Requester
from core.crawler import Crawler
from reporting.reporter import Reporter
from scoring.scorer import Scorer

from checks.headers import HeadersCheck
from checks.cookies import CookiesCheck
from checks.tls_https import TLSHttpsCheck
from checks.cors import CORSCheck
from checks.info_leak import InfoLeakCheck
from checks.sensitive_paths import SensitivePathsCheck
from checks.forms import FormsCheck
from checks.reflection import ReflectionCheck


def parse_args():
    p = argparse.ArgumentParser(
        prog="CoreInspect",
        description="CoreInspect - Web Security Auditor (passive + non-destructive active checks).",
    )
    p.add_argument("--target", required=True, help="Target URL (e.g., https://example.com)")
    p.add_argument("--profile", choices=["passive", "active", "deep"], default="passive")
    p.add_argument("--max-pages", type=int, default=25)
    p.add_argument("--timeout", type=int, default=12)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--rate", type=float, default=2.0, help="Max requests per second (approx).")
    p.add_argument("--headless", action="store_true", default=True, help="Run Playwright headless (default true).")
    p.add_argument("--no-headless", action="store_false", dest="headless", help="Run with visible browser.")
    p.add_argument("--out", default="reports", help="Output directory")
    p.add_argument("--format", choices=["txt", "json", "both"], default="both")
    p.add_argument("--authorized", action="store_true", help="Confirm you are authorized to test this target.")
    p.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO")
    return p.parse_args()


def normalize_target(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")


def main():
    args = parse_args()
    target = normalize_target(args.target)

    setup_logging(level=args.log_level)
    log = get_logger(__name__)

    if args.profile in ("active", "deep") and not args.authorized:
        log.error("Active/Deep profiles require --authorized.")
        log.error("Run with --authorized only if you have explicit permission to test the target.")
        return 2

    parsed = urlparse(target)
    if not parsed.netloc:
        log.error("Invalid target URL: %s", target)
        return 2

    config = ScanConfig(
        target=target,
        profile=args.profile,
        max_pages=args.max_pages,
        timeout=args.timeout,
        concurrency=args.concurrency,
        rate_limit_rps=args.rate,
        headless=args.headless,
        out_dir=args.out,
        output_format=args.format,
        authorized=args.authorized,
    )

    req = Requester(timeout=config.timeout, rate_limit_rps=config.rate_limit_rps)
    reporter = Reporter(config=config)
    scorer = Scorer()

    # Crawl (dynamic via Playwright)
    crawler = Crawler(target_url=config.target, headless=config.headless, timeout_ms=config.timeout * 1000)
    visited_urls, forms = crawler.crawl(max_pages=config.max_pages)

    # Always run passive checks on the main page first (baseline)
    checks = [
        TLSHttpsCheck(req, reporter),
        HeadersCheck(req, reporter),
        CookiesCheck(req, reporter),
        CORSCheck(req, reporter),
        InfoLeakCheck(req, reporter),
        SensitivePathsCheck(req, reporter),
        FormsCheck(req, reporter),
    ]

    # Non-destructive active checks
    if config.profile in ("active", "deep"):
        checks.append(ReflectionCheck(req, reporter))

    # Run checks
    log.info("Running checks on %d URLs and %d forms...", len(visited_urls), len(forms))

    # URL-level checks
    for url in sorted(visited_urls):
        for check in checks:
            check.run_url(url)

    # Form-level checks
    for form in forms:
        for check in checks:
            check.run_form(form)

    # Score
    score_result = scorer.compute(reporter.findings, target=config.target)
    reporter.set_score(score_result)

    # Save reports
    reporter.save()

    log.info("Done. Score: %s/100 (%s)", score_result.score, score_result.grade)
    return 0


if __name__ == "__main__":
    sys.exit(main())