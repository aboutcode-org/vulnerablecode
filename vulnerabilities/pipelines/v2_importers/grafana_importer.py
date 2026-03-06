#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import logging
import re
from datetime import datetime
from datetime import timezone
from typing import Iterable

from packageurl import PackageURL
from univers.version_range import build_range_from_github_advisory_constraint

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import get_cwe_id

logger = logging.getLogger(__name__)

# Repos tracked per issue #1462: grafana/grafana, grafana/loki,
# credativ/plutono (Grafana fork), credativ/vali (Loki fork).
GRAFANA_REPOS = [
    ("grafana", "grafana", "golang", "github.com/grafana/grafana"),
    ("grafana", "loki", "golang", "github.com/grafana/loki"),
    ("credativ", "plutono", "golang", "github.com/credativ/plutono"),
    ("credativ", "vali", "golang", "github.com/credativ/vali"),
]

GITHUB_ADVISORY_API = (
    "https://api.github.com/repos/{owner}/{repo}/security-advisories?per_page=100&page={page}"
)


class GrafanaImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline-based importer for Grafana security advisories from the GitHub
    Security Advisory REST API. Covers grafana/grafana, grafana/loki,
    credativ/plutono, and credativ/vali.
    """

    pipeline_id = "grafana_importer"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/grafana/grafana/blob/main/LICENSE"
    repo_url = "https://github.com/grafana/grafana"
    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        count = 0
        for owner, repo, _, _ in GRAFANA_REPOS:
            page = 1
            while True:
                url = GITHUB_ADVISORY_API.format(owner=owner, repo=repo, page=page)
                try:
                    advisories = fetch_response(url).json()
                except Exception as e:
                    logger.error("Failed to fetch advisories from %s: %s", url, e)
                    break
                if not advisories:
                    break
                count += sum(1 for a in advisories if a.get("state") == "published")
                if len(advisories) < 100:
                    break
                page += 1
        return count

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for owner, repo, purl_type, purl_namespace in GRAFANA_REPOS:
            yield from fetch_grafana_advisories(
                owner=owner,
                repo=repo,
                purl_type=purl_type,
                purl_namespace=purl_namespace,
            )


def fetch_grafana_advisories(
    owner: str,
    repo: str,
    purl_type: str,
    purl_namespace: str,
) -> Iterable[AdvisoryDataV2]:
    """
    Paginate through the GitHub Security Advisory REST API for the given
    owner/repo and yield parsed AdvisoryDataV2 objects.
    """
    page = 1
    while True:
        url = GITHUB_ADVISORY_API.format(owner=owner, repo=repo, page=page)
        try:
            advisories = fetch_response(url).json()
        except Exception as e:
            logger.error("Failed to fetch advisories from %s: %s", url, e)
            break
        if not advisories:
            break
        for advisory in advisories:
            if advisory.get("state") != "published":
                continue
            parsed = parse_advisory_data(
                advisory=advisory,
                purl_type=purl_type,
                purl_namespace=purl_namespace,
            )
            if parsed:
                yield parsed
        if len(advisories) < 100:
            break
        page += 1


def parse_advisory_data(advisory: dict, purl_type: str, purl_namespace: str):
    """
    Parse a GitHub Security Advisory REST API response for a Grafana repo and
    return an AdvisoryDataV2 object, or None if parsing fails.

    ``advisory_id`` is set to the GHSA ID; any CVE ID goes into ``aliases``.
    Version ranges from the API (space-separated constraints) are normalized to
    comma-separated format before being passed to
    ``build_range_from_github_advisory_constraint``.

    >>> advisory = {
    ...     "ghsa_id": "GHSA-7rqg-hjwc-6mjf",
    ...     "cve_id": "CVE-2023-22462",
    ...     "html_url": "https://github.com/grafana/grafana/security/advisories/GHSA-7rqg-hjwc-6mjf",
    ...     "summary": "Stored XSS in Text plugin",
    ...     "description": "An attacker needs Editor role.",
    ...     "severity": "medium",
    ...     "state": "published",
    ...     "published_at": "2023-03-01T08:59:53Z",
    ...     "vulnerabilities": [
    ...         {
    ...             "package": {"ecosystem": "", "name": "github.com/grafana/grafana"},
    ...             "vulnerable_version_range": ">=9.2.0 <9.2.10",
    ...             "patched_versions": "9.2.10",
    ...             "vulnerable_functions": []
    ...         }
    ...     ],
    ...     "cvss_severities": {
    ...         "cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:N", "score": 6.4},
    ...         "cvss_v4": {"vector_string": None, "score": None}
    ...     },
    ...     "cwes": [{"cwe_id": "CWE-79", "name": "Cross-site Scripting"}],
    ...     "identifiers": [
    ...         {"value": "GHSA-7rqg-hjwc-6mjf", "type": "GHSA"},
    ...         {"value": "CVE-2023-22462", "type": "CVE"}
    ...     ]
    ... }
    >>> result = parse_advisory_data(advisory, "golang", "github.com/grafana/grafana")
    >>> result.advisory_id
    'GHSA-7rqg-hjwc-6mjf'
    >>> result.aliases
    ['CVE-2023-22462']
    >>> result.summary
    'Stored XSS in Text plugin'
    """
    ghsa_id = advisory.get("ghsa_id") or ""
    cve_id = advisory.get("cve_id") or ""
    html_url = advisory.get("html_url") or ""
    summary = advisory.get("summary") or ""
    published_at = advisory.get("published_at") or ""

    if not ghsa_id:
        logger.error("Advisory has no GHSA ID, skipping.")
        return None

    aliases = []
    if cve_id:
        aliases.append(cve_id)

    date_published = None
    if published_at:
        try:
            date_published = datetime.strptime(published_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            logger.error("Cannot parse date %r for %s", published_at, ghsa_id)

    cvss_v3 = (advisory.get("cvss_severities") or {}).get("cvss_v3") or {}
    cvss_vector = cvss_v3.get("vector_string") or ""
    cvss_score = cvss_v3.get("score")

    severities = []
    if cvss_vector:
        severities.append(
            VulnerabilitySeverity(
                system=SCORING_SYSTEMS["cvssv3.1"],
                value=str(cvss_score) if cvss_score is not None else "",
                scoring_elements=cvss_vector,
            )
        )

    references = []
    if html_url:
        references.append(ReferenceV2(url=html_url))

    weaknesses = []
    for cwe in advisory.get("cwes") or []:
        cwe_string = cwe.get("cwe_id") or ""
        if cwe_string:
            cwe_int = get_cwe_id(cwe_string)
            if cwe_int:
                weaknesses.append(cwe_int)

    affected_packages = []
    for vuln in advisory.get("vulnerabilities") or []:
        pkg_name = (vuln.get("package") or {}).get("name") or purl_namespace
        if not pkg_name:
            pkg_name = purl_namespace

        raw_range = vuln.get("vulnerable_version_range") or ""
        version_range = None
        if raw_range:
            # Normalize space-separated constraints to comma-separated format.
            # Example: ">=9.2.0 <9.2.10 >=9.3.0 <9.3.4" -> ">=9.2.0, <9.2.10, >=9.3.0, <9.3.4"
            normalized = re.sub(r"\s+(?=[<>!=])", ", ", raw_range.strip())
            try:
                version_range = build_range_from_github_advisory_constraint(
                    purl_type, normalized
                )
            except Exception as e:
                logger.error(
                    "Cannot parse version range %r for %s: %s", raw_range, ghsa_id, e
                )

        if version_range is None:
            continue

        purl = PackageURL(type=purl_type, namespace="", name=pkg_name)
        try:
            affected_packages.append(
                AffectedPackageV2(
                    package=purl,
                    affected_version_range=version_range,
                )
            )
        except ValueError as e:
            logger.error("Cannot create AffectedPackageV2 for %s: %s", ghsa_id, e)

    return AdvisoryDataV2(
        advisory_id=ghsa_id,
        aliases=aliases,
        summary=summary,
        affected_packages=affected_packages,
        references=references,
        date_published=date_published,
        weaknesses=weaknesses,
        severities=severities,
        url=html_url,
        original_advisory_text=json.dumps(advisory, indent=2, ensure_ascii=False),
    )
