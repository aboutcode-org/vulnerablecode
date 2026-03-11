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
from typing import Iterable

import dateparser
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

# repos from issue #1462: grafana, loki, plutono (fork), vali (fork)
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
    """Collect Grafana security advisories from the GitHub Security Advisory API."""

    pipeline_id = "grafana_importer"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/grafana/grafana/blob/main/LICENSE"
    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        return 0

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
    """Paginate GitHub advisory API for the given repo and yield parsed advisories."""
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
    """Parse a GitHub advisory dict; return None if GHSA ID is missing."""
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
        date_published = dateparser.parse(published_at)
        if date_published is None:
            logger.warning("Could not parse date %r for advisory %s", published_at, ghsa_id)

    cvss_v3 = (advisory.get("cvss_severities") or {}).get("cvss_v3") or {}
    cvss_vector = cvss_v3.get("vector_string") or ""
    cvss_score = cvss_v3.get("score")

    severities = []
    if cvss_vector:
        system = (
            SCORING_SYSTEMS["cvssv3.1"]
            if cvss_vector.startswith("CVSS:3.1/")
            else SCORING_SYSTEMS["cvssv3"]
        )
        severities.append(
            VulnerabilitySeverity(
                system=system,
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

        raw_range = vuln.get("vulnerable_version_range") or ""
        version_range = None
        if raw_range:
            # space-separated API constraints must be comma-separated for range parsing
            normalized = re.sub(r"\s+(?=[<>!=])", ", ", raw_range.strip())
            try:
                version_range = build_range_from_github_advisory_constraint(purl_type, normalized)
            except Exception as e:
                logger.error("Cannot parse version range %r for %s: %s", raw_range, ghsa_id, e)

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
