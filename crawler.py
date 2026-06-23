#!/usr/bin/env python3
"""
Automated crawler for reconnaissance.
Extracts forms, parameters, URLs from target website.
"""
import re
import json
import time
import logging
from typing import Any
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse
from html.parser import HTMLParser
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


class PageParser(HTMLParser):
    """Extract forms, links, parameters, meta tags from HTML."""
    SKIP_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
        '.css', '.js', '.pdf', '.zip', '.tar', '.gz', '.mp4',
        '.mp3', '.woff', '.woff2', '.ttf', '.eot',
    }

    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self.meta_tags = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attr = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()

        if tag == "form":
            self.current_form = {
                "method": attr.get("method", "post").upper(),
                "action": attr.get("action", ""),
                "enctype": attr.get("enctype", "application/x-www-form-urlencoded"),
                "inputs": []
            }
            self.forms.append(self.current_form)

        elif tag in {"input", "textarea", "select"} and self.current_form:
            self.current_form["inputs"].append({
                "name": attr.get("name", ""),
                "type": attr.get("type", "text"),
                "value": attr.get("value", ""),
            })

        elif tag == "a":
            href = attr.get("href", "")
            if href:
                self.links.append(href)

        elif tag == "meta":
            self.meta_tags.append(attr)

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self.current_form = None

    @staticmethod
    def _should_skip_url(url: str) -> bool:
        """Skip static assets and fragment-only links."""
        parsed = urlparse(url)
        if parsed.fragment and not parsed.path:
            return True
        path_lower = parsed.path.lower()
        for ext in PageParser.SKIP_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        return False


class Crawler:
    def __init__(self, target_url: str, timeout: int = 10, verify_ssl: bool = False,
                 on_progress: Any = None):
        self.target_url = target_url
        self.base_url = self._normalize_url(target_url)
        self.domain = urlparse(self.base_url).netloc
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.visited_urls = set()
        self.pages: list[tuple[str, str, int]] = []  # [(url, html, status), ...]
        self.all_forms = []
        self.all_params = []
        self.errors: list[str] = []
        self.on_progress = on_progress  # callback(message: str)

        # Session with retries
        self.session = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[503, 429])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        })

    def _notify(self, msg: str):
        if self.on_progress:
            try:
                self.on_progress(msg)
            except Exception:
                pass

    def _normalize_url(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        return url.rstrip("/")

    @staticmethod
    def _strip_fragment(url: str) -> str:
        """Remove fragment from URL for dedup purposes."""
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment=""))

    def _same_domain(self, url: str) -> bool:
        """Check if URL belongs to same domain."""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.domain or parsed.netloc == ""
        except Exception:
            return False

    def fetch(self, url: str, follow_redirects: bool = True) -> tuple[str, str, int]:
        """Fetch a URL, return (url, html, status_code)."""
        if url in self.visited_urls:
            return url, "", 304

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=follow_redirects
            )
            self.visited_urls.add(url)
            return resp.url, resp.text, resp.status_code
        except Exception as e:
            return url, f"<!-- Error: {str(e)} -->", 0

    def crawl(self, max_pages: int = 50, max_depth: int = 3) -> dict[str, Any]:
        """Crawl the target site breadth-first."""
        to_visit = [self.base_url]
        depth = {self.base_url: 0}
        count = 0

        self._notify(f"Starting crawl of {self.base_url}")

        while to_visit and count < max_pages:
            url = to_visit.pop(0)
            current_depth = depth.get(url, 0)

            if current_depth > max_depth:
                continue

            url = urljoin(self.base_url, url)
            url = self._strip_fragment(url)
            if url in self.visited_urls:
                continue

            self._notify(f"Crawling page {count + 1}: {url[:80]}")
            final_url, html, status = self.fetch(url)
            if status == 0:
                self.errors.append(f"Failed to fetch: {url}")
                continue
            if status >= 400:
                self.errors.append(f"HTTP {status}: {url}")
                continue

            count += 1
            self.pages.append((final_url, html, status))

            # Parse HTML
            parser = PageParser()
            try:
                parser.feed(html)
            except Exception as e:
                self.errors.append(f"Parse error on {url}: {e}")
                continue

            # Extract forms
            for form in parser.forms:
                form["url"] = final_url
                self.all_forms.append(form)

            # Queue new URLs (breadth-first: append to end)
            for link in parser.links:
                if PageParser._should_skip_url(link):
                    continue
                abs_link = urljoin(final_url, link)
                abs_link = self._strip_fragment(abs_link)
                if self._same_domain(abs_link) and abs_link not in self.visited_urls:
                    if abs_link not in to_visit:
                        to_visit.append(abs_link)
                        depth[abs_link] = current_depth + 1

            # Extract URL parameters
            parsed = urlparse(final_url)
            if parsed.query:
                for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
                    for val in values:
                        self.all_params.append({
                            "url": final_url,
                            "location": "query",
                            "name": key,
                            "value": val,
                            "method": "GET"
                        })

        self._notify(f"Crawl complete: {count} pages, {len(self.all_forms)} forms, "
                     f"{len(self.all_params)} params")

        return {
            "target": self.target_url,
            "base_url": self.base_url,
            "pages_crawled": count,
            "pages": self.pages,  # full (url, html, status) tuples
            "pages_summary": [(u, len(h), s) for u, h, s in self.pages],  # lightweight
            "forms": self.all_forms,
            "params": self.all_params,
            "errors": self.errors,
        }

    def generate_test_requests(self) -> list[dict[str, Any]]:
        """Generate HTTP requests to test (from forms and parameters)."""
        requests_to_test = []

        # Test each form
        for form in self.all_forms:
            form_url = form.get("url", self.base_url)
            method = form.get("method", "POST")
            action = form.get("action", "")
            target_url = urljoin(form_url, action) if action else form_url

            # Build test data for each input
            data = {}
            for inp in form.get("inputs", []):
                name = inp.get("name", "")
                inp_type = inp.get("type", "text").lower()
                if not name:
                    continue
                # Generate test payload based on input type
                if inp_type == "email":
                    data[name] = "test@example.com'"
                elif inp_type == "password":
                    data[name] = "password123'"
                elif inp_type == "number":
                    data[name] = "1' OR '1'='1"
                elif inp_type == "file":
                    data[name] = "../../../etc/passwd"
                else:
                    data[name] = "test' OR '1'='1"

            requests_to_test.append({
                "method": method,
                "url": target_url,
                "data": data,
                "type": "form",
                "source": form_url
            })

        # Test URL parameters
        for param in self.all_params:
            test_payload = "test' OR '1'='1"
            test_url = param["url"] + (
                f"?{param['name']}={test_payload}" if "?" not in param["url"]
                else f"&{param['name']}={test_payload}"
            )
            requests_to_test.append({
                "method": "GET",
                "url": test_url,
                "data": None,
                "type": "url_param",
                "param_name": param["name"],
                "source": param["url"]
            })

        return requests_to_test


def crawl_and_extract(target: str, max_pages: int = 30,
                       on_progress: Any = None) -> dict[str, Any]:
    """Main entry point: crawl target and extract testable requests."""
    c = Crawler(target, verify_ssl=False, on_progress=on_progress)
    result = c.crawl(max_pages=max_pages, max_depth=2)
    result["test_requests"] = c.generate_test_requests()
    return result
