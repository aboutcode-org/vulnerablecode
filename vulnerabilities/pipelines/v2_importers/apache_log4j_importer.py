#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timezone
from typing import Iterable
from xml.etree import ElementTree

import requests
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import CVSSV31
from vulnerabilities.severity_systems import CVSSV4

logger = logging.getLogger(__name__)

VDR_URL = "https://logging.apache.org/cyclonedx/vdr.xml"
CDX_NS = "http://cyclonedx.org/schema/bom/1.6"

# Map the <method> element text in the VDR to scoring system objects.
CVSS_METHOD_MAP = {
    "CVSSv3": CVSSV3,
    "CVSSv3.1": CVSSV31,
    "CVSSv4": CVSSV4,
}


class ApacheLog4jImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect Apache Log4j security advisories from the CycloneDX VDR file."""

    pipeline_id = "apache_log4j_importer_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/LICENSE-2.0"
    url = VDR_URL

    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        response = requests.get(self.url, timeout=30)
        response.raise_for_status()
        root = ElementTree.fromstring(response.content)
        vulns = root.find(f"{{{CDX_NS}}}vulnerabilities")
        if vulns is None:
            return 0
        return len(list(vulns.findall(f"{{{CDX_NS}}}vulnerability")))

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        response = requests.get(self.url, timeout=30)
        response.raise_for_status()
        root = ElementTree.fromstring(response.content)
        vulns = root.find(f"{{{CDX_NS}}}vulnerabilities")
        if vulns is None:
            logger.warning("No <vulnerabilities> element found in VDR XML")
            return
        for vuln in vulns.findall(f"{{{CDX_NS}}}vulnerability"):
            try:
                advisory = parse_advisory(vuln)
                if advisory:
                    yield advisory
            except Exception as e:
                cve_id = (vuln.findtext(f"{{{CDX_NS}}}id") or "unknown").strip()
                logger.error(f"Failed to parse advisory {cve_id}: {e}")


def parse_advisory(vuln_el) -> AdvisoryDataV2:
    """
    Parse a single <vulnerability> element from the Log4j CycloneDX VDR XML.

    Returns an AdvisoryDataV2, or None if the entry has no CVE ID.
    """
    cve_id = (vuln_el.findtext(f"{{{CDX_NS}}}id") or "").strip()
    if not cve_id:
        return None

    description = (vuln_el.findtext(f"{{{CDX_NS}}}description") or "").strip()
    published_raw = (vuln_el.findtext(f"{{{CDX_NS}}}published") or "").strip()
    date_published = parse_date(published_raw)

    severities = parse_severities(vuln_el)
    weaknesses = parse_weaknesses(vuln_el)
    affected_packages = parse_affected_packages(vuln_el)
    references = parse_references(vuln_el, cve_id)

    return AdvisoryDataV2(
        advisory_id=cve_id,
        aliases=[],
        summary=description,
        affected_packages=affected_packages,
        references=references,
        severities=severities,
        weaknesses=weaknesses,
        date_published=date_published,
        url=VDR_URL,
        original_advisory_text=ElementTree.tostring(vuln_el, encoding="unicode"),
    )


def parse_date(raw):
    """
    Parse an ISO 8601 timestamp string and return a UTC-aware datetime, or None.

    >>> parse_date("2021-12-10T00:00:00Z")
    datetime.datetime(2021, 12, 10, 0, 0, tzinfo=datetime.timezone.utc)
    >>> parse_date("") is None
    True
    >>> parse_date("bad") is None
    True
    """
    if not raw:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def parse_severities(vuln_el):
    """
    Return a list of VulnerabilitySeverity objects from the <ratings> element.

    Each <rating> has a <score>, <method>, and <vector>. We map method strings
    like "CVSSv3", "CVSSv3.1", "CVSSv4" to scoring system objects.
    """
    severities = []
    ratings_el = vuln_el.find(f"{{{CDX_NS}}}ratings")
    if ratings_el is None:
        return severities
    for rating_el in ratings_el.findall(f"{{{CDX_NS}}}rating"):
        score = (rating_el.findtext(f"{{{CDX_NS}}}score") or "").strip()
        method = (rating_el.findtext(f"{{{CDX_NS}}}method") or "").strip()
        vector = (rating_el.findtext(f"{{{CDX_NS}}}vector") or "").strip()
        system = CVSS_METHOD_MAP.get(method)
        if not system:
            logger.warning(f"Unknown CVSS method: {method!r}")
            continue
        severities.append(
            VulnerabilitySeverity(
                system=system,
                value=score,
                scoring_elements=vector,
            )
        )
    return severities


def parse_weaknesses(vuln_el):
    """
    Return a list of integer CWE IDs from the <cwes> element.

    >>> import xml.etree.ElementTree as ET
    >>> xml = '<vulnerability xmlns="http://cyclonedx.org/schema/bom/1.6"><cwes><cwe>20</cwe><cwe>502</cwe></cwes></vulnerability>'
    >>> el = ET.fromstring(xml)
    >>> parse_weaknesses(el)
    [20, 502]
    >>> xml2 = '<vulnerability xmlns="http://cyclonedx.org/schema/bom/1.6"></vulnerability>'
    >>> parse_weaknesses(ET.fromstring(xml2))
    []
    """
    weaknesses = []
    cwes_el = vuln_el.find(f"{{{CDX_NS}}}cwes")
    if cwes_el is None:
        return weaknesses
    for cwe_el in cwes_el.findall(f"{{{CDX_NS}}}cwe"):
        text = (cwe_el.text or "").strip()
        if text.isdigit():
            weaknesses.append(int(text))
    return weaknesses


def parse_affected_packages(vuln_el):
    """
    Return a list of AffectedPackageV2 from the <affects> element.

    Each <target> has a PURL <ref> and one or more <version><range> elements
    in VERS format (e.g. "vers:maven/>=2.0-beta9|<2.15.0"). We create one
    AffectedPackageV2 per VERS range.
    """
    affected_packages = []
    affects_el = vuln_el.find(f"{{{CDX_NS}}}affects")
    if affects_el is None:
        return affected_packages
    for target_el in affects_el.findall(f"{{{CDX_NS}}}target"):
        ref_text = (target_el.findtext(f"{{{CDX_NS}}}ref") or "").strip()
        if not ref_text:
            continue
        try:
            purl = PackageURL.from_string(ref_text)
        except Exception as e:
            logger.warning(f"Could not parse PURL {ref_text!r}: {e}")
            continue

        versions_el = target_el.find(f"{{{CDX_NS}}}versions")
        if versions_el is None:
            continue
        for version_el in versions_el.findall(f"{{{CDX_NS}}}version"):
            range_text = (version_el.findtext(f"{{{CDX_NS}}}range") or "").strip()
            if not range_text:
                continue
            try:
                version_range = VersionRange.from_string(range_text)
            except Exception as e:
                logger.warning(f"Could not parse VERS range {range_text!r}: {e}")
                continue
            affected_packages.append(
                AffectedPackageV2(
                    package=purl,
                    affected_version_range=version_range,
                )
            )
    return affected_packages


def parse_references(vuln_el, cve_id):
    """
    Return a list of ReferenceV2 from the <source> NVD URL and any <references> entries.
    """
    references = []

    source_el = vuln_el.find(f"{{{CDX_NS}}}source")
    if source_el is not None:
        nvd_url = (source_el.findtext(f"{{{CDX_NS}}}url") or "").strip()
        if nvd_url:
            references.append(ReferenceV2(reference_id=cve_id, url=nvd_url))

    refs_el = vuln_el.find(f"{{{CDX_NS}}}references")
    if refs_el is not None:
        for ref_el in refs_el.findall(f"{{{CDX_NS}}}reference"):
            ref_id = (ref_el.findtext(f"{{{CDX_NS}}}id") or "").strip()
            src_el = ref_el.find(f"{{{CDX_NS}}}source")
            ref_url = ""
            if src_el is not None:
                ref_url = (src_el.findtext(f"{{{CDX_NS}}}url") or "").strip()
            if ref_url:
                references.append(ReferenceV2(reference_id=ref_id, url=ref_url))

    return references
