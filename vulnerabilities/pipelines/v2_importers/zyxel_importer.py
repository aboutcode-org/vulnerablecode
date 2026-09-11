#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib
import logging
import re
from datetime import timezone
from urllib.parse import urljoin
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from dateutil import parser as date_parser

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import dedupe
from vulnerabilities.utils import find_all_cve

logger = logging.getLogger(__name__)


class ZyxelImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Importer for ZyXEL security advisories pages."""

    pipeline_id = "zyxel_importer_v2"
    base_url = "https://www.zyxel.com/global/en/support/security-advisories"
    spdx_license_expression = "NOASSERTION"
    license_url = base_url

    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )

    def fetch(self):
        self.log(f"Fetch `{self.base_url}`")
        try:
            response = requests.get(self.base_url, timeout=30)
            response.raise_for_status()
            self.listing_html = response.text
        except requests.exceptions.Timeout:
            self.log(f"Timeout while fetching {self.base_url}")
            raise
        except requests.exceptions.HTTPError as e:
            self.log(f"HTTP error while fetching {self.base_url}: {e!r}")
            raise
        except requests.exceptions.RequestException as e:
            self.log(f"Network error while fetching {self.base_url}: {e!r}")
            raise

    def advisories_count(self):
        return len(parse_listing_for_advisory_urls(self.listing_html, self.base_url))

    def collect_advisories(self):
        for advisory_url in parse_listing_for_advisory_urls(self.listing_html, self.base_url):
            try:
                response = requests.get(advisory_url, timeout=30)
                response.raise_for_status()
                raw_html = response.text
                advisory = parse_zyxel_advisory_page(raw_html=raw_html, advisory_url=advisory_url)
                if advisory:
                    yield advisory
            except requests.exceptions.Timeout:
                self.log(f"Timeout while fetching ZyXEL advisory at {advisory_url}")
            except requests.exceptions.HTTPError as e:
                self.log(f"HTTP error while fetching ZyXEL advisory at {advisory_url}: {e!r}")
            except requests.exceptions.RequestException as e:
                self.log(f"Network error while fetching ZyXEL advisory at {advisory_url}: {e!r}")
            except Exception as e:
                self.log(f"Unexpected error parsing ZyXEL advisory at {advisory_url}: {e!r}")


def parse_listing_for_advisory_urls(raw_html, base_url):
    """Return sorted advisory detail URLs from the ZyXEL listing page HTML."""
    soup = BeautifulSoup(raw_html, features="lxml")
    found_urls = set()

    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "").strip()
        if not href:
            continue

        absolute_url = urljoin(base_url, href)
        parsed = urlparse(absolute_url)
        slug = parsed.path.rstrip("/").split("/")[-1].lower()

        if "support/security-advisories" not in absolute_url.lower():
            continue

        if slug == "security-advisories":
            continue

        found_urls.add(absolute_url)

    return sorted(found_urls)


def parse_zyxel_advisory_page(raw_html, advisory_url):
    """Parse a ZyXEL advisory detail page and return AdvisoryDataV2."""
    soup = BeautifulSoup(raw_html, features="lxml")
    page_text = soup.get_text(" ", strip=True)

    aliases = [alias.upper() for alias in find_all_cve(page_text)]
    aliases = dedupe(aliases)

    summary = extract_summary(soup=soup)
    date_published = extract_published_date(soup=soup, page_text=page_text)
    advisory_id = get_advisory_id(
        advisory_url=advisory_url,
        aliases=aliases,
        summary=summary,
        date_published=date_published,
    )

    references = get_references(soup=soup, advisory_url=advisory_url, aliases=aliases)

    return AdvisoryDataV2(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=summary,
        references=references,
        date_published=date_published,
        url=advisory_url,
        original_advisory_text=raw_html,
    )


def extract_summary(soup):
    h1 = soup.find("h1")
    if h1 and h1.get_text(strip=True):
        return h1.get_text(" ", strip=True)

    title = soup.find("title")
    if title and title.get_text(strip=True):
        return title.get_text(" ", strip=True)

    return "ZyXEL security advisory"


def extract_published_date(soup, page_text):
    for key, value in (
        ("property", "article:published_time"),
        ("name", "article:published_time"),
        ("name", "publish_date"),
        ("name", "date"),
    ):
        meta = soup.find("meta", attrs={key: value})
        if not meta:
            continue

        content = (meta.get("content") or "").strip()
        if not content:
            continue

        parsed = date_parser.parse(content)
        if parsed:
            if not parsed.tzinfo:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed

    match = re.search(r"(?:published|release date)\s*:?\s*([A-Za-z0-9, :\-+/]+)", page_text, re.I)
    if not match:
        return None

    parsed = date_parser.parse(match.group(1).strip())
    if parsed and not parsed.tzinfo:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def get_advisory_id(advisory_url, aliases, summary, date_published):
    slug = urlparse(advisory_url).path.rstrip("/").split("/")[-1]
    if slug and slug.lower() != "security-advisories":
        return f"zyxel-{slug}"

    published = date_published.isoformat() if date_published else ""
    digest = hashlib.sha1(
        f"{advisory_url}|{summary}|{published}|{'|'.join(aliases)}".encode("utf-8")
    ).hexdigest()[:16]
    return f"zyxel-{digest}"


def get_references(soup, advisory_url, aliases):
    urls = [advisory_url]

    for alias in aliases:
        urls.append(f"https://nvd.nist.gov/vuln/detail/{alias}")

    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "").strip()
        if not href:
            continue

        absolute_url = urljoin(advisory_url, href)
        if absolute_url.startswith("http"):
            urls.append(absolute_url)

    deduped_urls = dedupe(urls)
    return [ReferenceV2(url=url) for url in deduped_urls]
