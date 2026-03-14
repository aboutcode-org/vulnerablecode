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
from datetime import datetime
from datetime import timezone
from typing import Iterable
from xml.etree import ElementTree

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import GenericVersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import CVSSV31

logger = logging.getLogger(__name__)

FEED_URL = "https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/rss"

ATOM_NS = "http://www.w3.org/2005/Atom"


class LiferayImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect Liferay security advisories from liferay.dev."""

    pipeline_id = "liferay_importer_v2"

    spdx_license_expression = "LicenseRef-scancode-unknown"
    license_url = "https://liferay.dev/portal/security/known-vulnerabilities"
    url = FEED_URL

    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        return 0

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        response = requests.get(self.url, timeout=30)
        response.raise_for_status()
        feed_text = response.text

        entries = parse_feed_entries(feed_text)
        for cve_id, advisory_url, published_raw in entries:
            if not cve_id:
                continue
            try:
                advisory = fetch_and_parse_advisory(cve_id, advisory_url, published_raw)
                if advisory:
                    yield advisory
            except Exception as e:
                logger.error(f"Failed to parse advisory for {cve_id} at {advisory_url}: {e}")


def parse_feed_entries(feed_text):
    """
    Parse Atom feed XML and return a list of (cve_id, url, published_raw) tuples.

    >>> xml = '''<?xml version="1.0"?>
    ... <feed xmlns="http://www.w3.org/2005/Atom">
    ...   <entry>
    ...     <title>CVE-2024-26268 User enumeration vulnerability</title>
    ...     <link href="https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/cve-2024-26268"/>
    ...     <published>2024-02-20T13:10:00Z</published>
    ...   </entry>
    ... </feed>'''
    >>> entries = parse_feed_entries(xml)
    >>> len(entries) == 1
    True
    >>> entries[0][0]
    'CVE-2024-26268'
    """
    root = ElementTree.fromstring(feed_text)
    results = []
    for entry in root.findall(f"{{{ATOM_NS}}}entry"):
        title_el = entry.find(f"{{{ATOM_NS}}}title")
        link_el = entry.find(f"{{{ATOM_NS}}}link[@rel='alternate']")
        if link_el is None:
            link_el = entry.find(f"{{{ATOM_NS}}}link")
        published_el = entry.find(f"{{{ATOM_NS}}}published")

        title = title_el.text.strip() if title_el is not None and title_el.text else ""
        url = link_el.attrib.get("href", "") if link_el is not None else ""
        published_raw = (
            published_el.text.strip() if published_el is not None and published_el.text else ""
        )

        cve_id = extract_cve_id(title)
        results.append((cve_id, url, published_raw))
    return results


def extract_cve_id(text):
    """
    Extract a CVE ID from text like "CVE-2024-26268 Some description".

    >>> extract_cve_id("CVE-2024-26268 User enumeration vulnerability")
    'CVE-2024-26268'
    >>> extract_cve_id("No CVE here")
    ''
    """
    match = re.search(r"CVE-\d{4}-\d+", text)
    return match.group(0) if match else ""


def fetch_and_parse_advisory(cve_id, advisory_url, published_raw):
    """
    Fetch an individual advisory page and return an AdvisoryDataV2 object, or None on failure.
    """
    response = requests.get(advisory_url, timeout=30)
    response.raise_for_status()
    return parse_advisory_page(cve_id, advisory_url, published_raw, response.text)


def parse_advisory_page(cve_id, advisory_url, published_raw, html):
    """
    Parse a Liferay advisory HTML page into an AdvisoryDataV2.

    The page has sections headed by <h3> tags:
        Description, Severity, Affected Version(s), Fixed Version(s)

    The Severity section contains text like:
        "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"
    """
    soup = BeautifulSoup(html, "lxml")

    sections = {}
    for h3 in soup.find_all("h3"):
        heading = h3.get_text(strip=True)
        sibling = h3.find_next_sibling()
        if sibling:
            sections[heading] = sibling

    summary = ""
    desc_el = sections.get("Description")
    if desc_el:
        summary = desc_el.get_text(strip=True)

    severities = []
    sev_el = sections.get("Severity")
    if sev_el:
        sev_text = sev_el.get_text(strip=True)
        severity = parse_severity(sev_text)
        if severity:
            severities.append(severity)

    affected_versions = []
    aff_el = sections.get("Affected Version(s)")
    if aff_el:
        affected_versions = [li.get_text(strip=True) for li in aff_el.find_all("li")]

    fixed_versions = []
    fix_el = sections.get("Fixed Version(s)")
    if fix_el:
        fixed_versions = [li.get_text(strip=True) for li in fix_el.find_all("li")]

    affected_packages = build_affected_packages(affected_versions, fixed_versions)

    references = [ReferenceV2(url=advisory_url)]

    date_published = parse_date(published_raw)

    return AdvisoryDataV2(
        advisory_id=cve_id,
        aliases=[],
        summary=summary,
        affected_packages=affected_packages,
        references=references,
        severities=severities,
        date_published=date_published,
        url=advisory_url,
        original_advisory_text=html,
    )


def parse_severity(sev_text):
    """
    Parse a Liferay severity string into a VulnerabilitySeverity.

    The format is: "5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)"

    >>> sev = parse_severity("5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)")
    >>> sev.value
    '5.3'
    >>> sev.scoring_elements
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'
    >>> parse_severity("") is None
    True
    """
    if not sev_text:
        return None

    match = re.match(r"^([\d.]+)\s*\((CVSS:[^)]+)\)", sev_text.strip())
    if match:
        score = match.group(1)
        vector = match.group(2)
        return VulnerabilitySeverity(
            system=CVSSV31,
            value=score,
            scoring_elements=vector,
        )

    match = re.match(r"^([\d.]+)", sev_text.strip())
    if match:
        return VulnerabilitySeverity(
            system=CVSSV31,
            value=match.group(1),
            scoring_elements="",
        )

    return None


def extract_version_numbers(text_list):
    """
    Extract the last dotted-numeric version string from each item in text_list.

    Liferay fixed-version strings look like "Liferay Portal 7.4.3.27" or
    "Liferay DXP 7.4 update 27". This function extracts the first dotted-numeric
    token that looks like a version (e.g. "7.4.3.27", "7.4").

    >>> extract_version_numbers(["Liferay Portal 7.4.3.27"])
    ['7.4.3.27']
    >>> extract_version_numbers(["Liferay Portal 7.4.0 through 7.4.3.26"])
    ['7.4.0', '7.4.3.26']
    >>> extract_version_numbers(["Liferay DXP 7.4 update 27"])
    ['7.4']
    >>> extract_version_numbers([])
    []
    """
    versions = []
    for text in text_list:
        found = re.findall(r"\b\d+(?:\.\d+)+\b", text)
        versions.extend(found)
    return versions


def build_affected_packages(affected_versions, fixed_versions):
    """
    Build a list of AffectedPackageV2 objects from plain-text version lists.

    Liferay Portal and Liferay DXP are tracked as separate generic packages.
    Version numbers are extracted from prose strings using a regex; ranges expressed
    as "X through Y" are captured as individual constraint points. The full prose
    is preserved in original_advisory_text on the advisory.
    """
    portal_affected = [v for v in affected_versions if "Liferay Portal" in v]
    portal_fixed = [v for v in fixed_versions if "Liferay Portal" in v]
    dxp_affected = [v for v in affected_versions if "Liferay DXP" in v]
    dxp_fixed = [v for v in fixed_versions if "Liferay DXP" in v]

    packages = []

    portal_pkg = PackageURL(type="generic", namespace="liferay.dev", name="liferay-portal")
    dxp_pkg = PackageURL(type="generic", namespace="liferay.dev", name="liferay-dxp")

    portal_affected_nums = extract_version_numbers(portal_affected)
    portal_fixed_nums = extract_version_numbers(portal_fixed)
    dxp_affected_nums = extract_version_numbers(dxp_affected)
    dxp_fixed_nums = extract_version_numbers(dxp_fixed)

    if portal_affected_nums or portal_fixed_nums:
        packages.append(
            AffectedPackageV2(
                package=portal_pkg,
                affected_version_range=GenericVersionRange.from_versions(portal_affected_nums)
                if portal_affected_nums
                else None,
                fixed_version_range=GenericVersionRange.from_versions(portal_fixed_nums)
                if portal_fixed_nums
                else None,
            )
        )
    elif portal_affected or portal_fixed:
        logger.warning(
            f"Could not extract version numbers from portal versions: "
            f"affected={portal_affected} fixed={portal_fixed}"
        )

    if dxp_affected_nums or dxp_fixed_nums:
        packages.append(
            AffectedPackageV2(
                package=dxp_pkg,
                affected_version_range=GenericVersionRange.from_versions(dxp_affected_nums)
                if dxp_affected_nums
                else None,
                fixed_version_range=GenericVersionRange.from_versions(dxp_fixed_nums)
                if dxp_fixed_nums
                else None,
            )
        )
    elif dxp_affected or dxp_fixed:
        logger.warning(
            f"Could not extract version numbers from DXP versions: "
            f"affected={dxp_affected} fixed={dxp_fixed}"
        )

    return packages


def parse_date(published_raw):
    """
    Parse an ISO 8601 date string and return a timezone-aware datetime, or None.

    >>> parse_date("2024-02-20T13:10:00Z")
    datetime.datetime(2024, 2, 20, 13, 10, tzinfo=datetime.timezone.utc)
    >>> parse_date("") is None
    True
    """
    if not published_raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(published_raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None
