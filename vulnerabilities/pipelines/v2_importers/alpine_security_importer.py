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
from typing import Iterable

import requests
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import AlpineLinuxVersionRange
from univers.versions import AlpineLinuxVersion
from univers.versions import InvalidVersion

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)

ALPINE_SECURITY_ROOT = "https://security.alpinelinux.org/"
BRANCH_URL = "https://security.alpinelinux.org/branch/{branch}"
ADVISORY_HEADERS = {"Accept": "application/ld+json"}

# EOL branches absent from root API index; 3.13-3.16 omitted (return 0 items)
HISTORICAL_BRANCHES = [
    "3.22-community",
    "3.18-main",
    "3.17-main",
    "3.12-main",
    "3.11-main",
    "3.10-main",
]


def get_branches() -> list:
    """Discover active branches from the root API and append HISTORICAL_BRANCHES."""
    try:
        resp = requests.get(ALPINE_SECURITY_ROOT, headers=ADVISORY_HEADERS, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # Branch entries have dict values; scalar values indicate non-branch keys.
        active = [k for k, v in data.items() if isinstance(v, dict)]
    except (requests.RequestException, ValueError) as e:
        logger.error("Failed to discover branches from root API: %s", e)
        active = []

    seen = set(active)
    return active + [b for b in HISTORICAL_BRANCHES if b not in seen]


class AlpineSecurityImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect Alpine Linux advisories from https://security.alpinelinux.org/."""

    pipeline_id = "alpine_security_importer"
    spdx_license_expression = "CC-BY-SA-4.0"
    license_url = "https://security.alpinelinux.org/"
    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        count = 0
        for branch in get_branches():
            url = BRANCH_URL.format(branch=branch)
            try:
                resp = requests.get(url, headers=ADVISORY_HEADERS, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except (requests.RequestException, ValueError) as e:
                logger.error("Failed to fetch branch %s: %s", branch, e)
                continue
            count += len(data.get("items") or [])
        return count

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for branch in get_branches():
            url = BRANCH_URL.format(branch=branch)
            try:
                resp = requests.get(url, headers=ADVISORY_HEADERS, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except (requests.RequestException, ValueError) as e:
                logger.error("Failed to fetch branch %s: %s", branch, e)
                continue
            for item in data.get("items") or []:
                advisory = parse_advisory(item)
                if advisory:
                    yield advisory


def parse_advisory(data: dict):
    """Parse a JSON-LD advisory; return None if the advisory ID is missing."""
    cve_url = data.get("id") or ""
    cve_id = cve_url.rstrip("/").split("/")[-1]
    if not cve_id:
        return None

    summary = data.get("description") or ""

    references = []
    for ref in data.get("ref") or []:
        ref_url = ref.get("rel") or ""
        if ref_url:
            references.append(
                ReferenceV2(
                    url=ref_url,
                    reference_type=ref.get("referenceType") or "",
                )
            )
    for cpe_match in data.get("cpeMatch") or []:
        cpe_uri = cpe_match.get("cpeUri") or ""
        cpe_id = cpe_match.get("id") or ""
        if cpe_uri and cpe_id:
            references.append(ReferenceV2(url=cpe_id, reference_id=cpe_uri))

    severities = []
    cvss3 = data.get("cvss3") or {}
    cvss_score = cvss3.get("score")
    cvss_vector = cvss3.get("vector") or ""
    if cvss_vector and cvss_score:
        if cvss_vector.startswith("CVSS:3.1/"):
            system = SCORING_SYSTEMS["cvssv3.1"]
        else:
            system = SCORING_SYSTEMS["cvssv3"]
        severities.append(
            VulnerabilitySeverity(
                system=system,
                value=str(cvss_score),
                scoring_elements=cvss_vector,
            )
        )

    states = data.get("state") or []
    fixed_repos = {state.get("repo") or "" for state in states if state.get("fixed")}

    affected_packages = []
    for state in states:
        is_fixed = state.get("fixed")
        repo = state.get("repo") or ""
        if not is_fixed and repo in fixed_repos:
            continue
        pkg_version_url = state.get("packageVersion") or ""
        parts = pkg_version_url.rstrip("/").split("/")
        if len(parts) < 2:
            continue
        pkg_name = parts[-2]
        version = parts[-1]
        if not pkg_name or not version:
            continue
        repo_parts = repo.split("-", 1)
        if len(repo_parts) != 2:
            continue
        version_tag, reponame = repo_parts
        distroversion = version_tag if version_tag == "edge" else f"v{version_tag}"
        purl = PackageURL(
            type="apk",
            namespace="alpine",
            name=pkg_name,
            qualifiers={"distroversion": distroversion, "reponame": reponame},
        )
        if is_fixed:
            try:
                fixed_version_range = AlpineLinuxVersionRange.from_versions([version])
            except InvalidVersion:
                logger.warning("Cannot parse Alpine version %r in %s", version, cve_id)
                continue
            affected_packages.append(
                AffectedPackageV2(
                    package=purl,
                    fixed_version_range=fixed_version_range,
                )
            )
        else:
            try:
                constraint = VersionConstraint(
                    comparator="<=",
                    version=AlpineLinuxVersion(version),
                )
                affected_version_range = AlpineLinuxVersionRange(constraints=(constraint,))
            except InvalidVersion:
                logger.warning("Cannot parse Alpine version %r in %s", version, cve_id)
                continue
            affected_packages.append(
                AffectedPackageV2(
                    package=purl,
                    affected_version_range=affected_version_range,
                )
            )

    return AdvisoryDataV2(
        advisory_id=cve_id,
        aliases=[],
        summary=summary,
        affected_packages=affected_packages,
        references=references,
        severities=severities,
        url=cve_url,
        original_advisory_text=json.dumps(data, indent=2, ensure_ascii=False),
    )
