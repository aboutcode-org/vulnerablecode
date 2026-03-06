#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
from typing import Iterable

import requests
from bs4 import BeautifulSoup

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference

logger = logging.getLogger(__name__)


class KdeImporter(Importer):
    spdx_license_expression = "LGPL-2.0-or-later"
    license_url = "https://kde.org/community/whatiskde/licensing/"
    importer_name = "KDE Importer"
    url = "https://kde.org/info/security/"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        advisory_urls = fetch_advisory_urls(self.url)
        for advisory_url in advisory_urls:
            try:
                advisory_text = fetch_advisory_text(advisory_url)
                advisory = parse_advisory(advisory_text, advisory_url)
                if advisory:
                    yield advisory
            except Exception as e:
                logger.error(f"Error parsing advisory {advisory_url}: {e}")


def fetch_advisory_urls(index_url):
    """
    Fetch all advisory URLs from the KDE security index page.

    Returns:
        List of full advisory URLs
    """
    response = requests.get(index_url)
    if response.status_code != 200:
        logger.error(f"Failed to fetch {index_url}")
        return []

    soup = BeautifulSoup(response.content, "html.parser")
    advisory_urls = []

    # Find all links in the page
    for link in soup.find_all("a"):
        href = link.get("href", "")
        # Advisory files end with .txt and start with advisory- or contain xpdf
        if href.endswith(".txt") and ("advisory-" in href or "xpdf" in href):
            # Convert relative URL to absolute
            if href.startswith("./"):
                href = href[2:]
            full_url = f"https://kde.org/info/security/{href}"
            advisory_urls.append(full_url)

    return advisory_urls


def fetch_advisory_text(advisory_url):
    """
    Fetch the text content of a KDE security advisory.

    Returns:
        Advisory text as string
    """
    response = requests.get(advisory_url)
    if response.status_code != 200:
        logger.error(f"Failed to fetch {advisory_url}")
        return None

    return response.text


def parse_advisory(advisory_text, advisory_url):
    """
    Parse a KDE security advisory and extract relevant information.

    Args:
        advisory_text: The full text content of the advisory
        advisory_url: URL of the advisory

    Returns:
        AdvisoryData object or None
    """
    if not advisory_text:
        return None

    # Extract CVE IDs (both CVE and old CAN format)
    cve_pattern = r'C(?:VE|AN)-\d{4}-\d{4,7}'
    cve_ids = re.findall(cve_pattern, advisory_text)

    # Convert old CAN format to CVE format
    aliases = []
    for cve_id in cve_ids:
        if cve_id.startswith("CAN-"):
            # CAN is old format, convert to CVE
            cve_id = cve_id.replace("CAN-", "CVE-")
        if cve_id not in aliases:
            aliases.append(cve_id)

    # Extract summary/title
    summary = extract_summary(advisory_text)

    # Extract references
    references = extract_references(advisory_text, advisory_url, aliases)

    # Only create advisory if we have CVE IDs or meaningful content
    if not aliases and not summary:
        logger.warning(f"No CVE IDs or summary found in {advisory_url}")
        return None

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        references=references,
        url=advisory_url,
    )


def extract_summary(advisory_text):
    """
    Extract the summary/title from the advisory text.
    """
    lines = advisory_text.split("\n")

    # Try to find Title: field (new format)
    for i, line in enumerate(lines):
        if line.startswith("Title:"):
            return line.replace("Title:", "").strip()

    # Try to find KDE Security Advisory: line (old format)
    for line in lines:
        if "KDE Security Advisory:" in line:
            return line.replace("KDE Security Advisory:", "").strip()

    # Try to find first non-empty line after PGP header
    skip_pgp = False
    for line in lines:
        if line.startswith("-----BEGIN PGP"):
            skip_pgp = True
            continue
        if skip_pgp and line.strip() and not line.startswith("Hash:"):
            skip_pgp = False
            continue
        if not skip_pgp and line.strip() and not line.startswith("---"):
            # Return first meaningful line as summary
            return line.strip()

    return ""


def extract_references(advisory_text, advisory_url, aliases):
    """
    Extract reference URLs from the advisory text.
    """
    references = []

    # Add the advisory itself as a reference
    references.append(Reference(url=advisory_url))

    # Add CVE references
    for cve_id in aliases:
        cve_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
        references.append(Reference(url=cve_url, reference_id=cve_id))

    # Extract URLs from text
    url_pattern = r'https?://[^\s<>"\')]+[^\s<>"\')\.]'
    urls = re.findall(url_pattern, advisory_text)

    for url in urls:
        # Skip if already added
        if any(ref.url == url for ref in references):
            continue
        # Add unique URLs
        references.append(Reference(url=url))

    return references
