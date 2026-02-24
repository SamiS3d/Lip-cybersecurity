from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from utils.colors import Colors


class Crawler:
    def __init__(self, target_url: str, headless: bool = True, timeout_ms: int = 12000):
        self.target_url = target_url
        self.visited_urls = set()
        self.forms = []
        self.domain = urlparse(target_url).netloc
        self.timeout_ms = timeout_ms
        self.headless = headless
        self.url_pattern = re.compile(r'href=[\'"]?([^\'" >]+)')

    def _in_scope(self, full_url: str) -> bool:
        try:
            return urlparse(full_url).netloc.endswith(self.domain)
        except Exception:
            return False

    def extract_links(self, url, html_content):
        links = set()
        soup = BeautifulSoup(html_content, "lxml")

        for anchor in soup.find_all("a", href=True):
            full_url = urljoin(url, anchor["href"])
            if self._in_scope(full_url):
                clean = full_url.split("#")[0]
                if clean not in self.visited_urls and clean.startswith(("http://", "https://")):
                    links.add(clean)

        matches = self.url_pattern.findall(html_content or "")
        for match in matches:
            full_url = urljoin(url, match)
            if self._in_scope(full_url) and full_url.startswith(("http://", "https://")):
                clean = full_url.split("#")[0]
                if clean not in self.visited_urls:
                    links.add(clean)

        return links

    def extract_forms(self, url, html_content):
        soup = BeautifulSoup(html_content, "lxml")
        for form in soup.find_all("form"):
            action = form.attrs.get("action", "")
            method = form.attrs.get("method", "get").lower()

            inputs = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                input_type = input_tag.attrs.get("type", "text")
                input_name = input_tag.attrs.get("name")
                if input_name:
                    inputs.append({"type": input_type, "name": input_name})

            form_details = {
                "action": urljoin(url, action),
                "method": method,
                "inputs": inputs,
                "url": url,
            }
            if form_details not in self.forms:
                self.forms.append(form_details)

    def crawl(self, max_pages=25):
        print(f"{Colors.INFO} Starting Dynamic Crawler (Playwright) on: {self.target_url}")
        urls_to_visit = [self.target_url]

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            page = browser.new_page()

            while urls_to_visit and len(self.visited_urls) < max_pages:
                current_url = urls_to_visit.pop(0)
                if current_url in self.visited_urls:
                    continue

                print(f"{Colors.INFO} Crawling: {current_url}")
                self.visited_urls.add(current_url)

                try:
                    page.goto(current_url, wait_until="networkidle", timeout=self.timeout_ms)
                    html = page.content() or ""

                    new_links = self.extract_links(current_url, html)
                    urls_to_visit.extend(sorted(new_links - self.visited_urls))
                    self.extract_forms(current_url, html)

                except PlaywrightTimeoutError:
                    print(f"{Colors.WARNING} Timeout: {current_url}")
                except Exception as e:
                    print(f"{Colors.ERROR} Error crawling {current_url}: {e}")

            browser.close()

        print(f"{Colors.SUCCESS} Crawling finished. Pages={len(self.visited_urls)}, Forms={len(self.forms)}")
        return self.visited_urls, self.forms