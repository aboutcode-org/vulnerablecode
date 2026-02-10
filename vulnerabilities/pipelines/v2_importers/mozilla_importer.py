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
from pathlib import Path
from typing import Iterable

import yaml
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from fetchcode.vcs import fetch_via_vcs
from markdown import markdown
from packageurl import PackageURL
from univers.version_range import GenericVersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import is_cve
from vulnerabilities.utils import split_markdown_front_matter

logger = logging.getLogger(__name__)

MFSA_FILENAME_RE = re.compile(r"mfsa(\d{4}-\d{2,3})\.(md|yml)$")


class MozillaImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline-based importer for Mozilla Foundation Security Advisories.
    """

    pipeline_id = "mozilla_importer_v2"
    repo_url = "git+https://github.com/mozilla/foundation-security-advisories"
    spdx_license_expression = "MPL-2.0"
    license_url = "https://github.com/mozilla/foundation-security-advisories/blob/master/LICENSE"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()

    def advisories_count(self) -> int:
        base_path = Path(self.vcs_response.dest_dir)
        yml = list((base_path / "announce").glob("**/*.yml"))
        md = list((base_path / "announce").glob("**/*.md"))
        return len(yml) + len(md)

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        base_path = Path(self.vcs_response.dest_dir)
        advisory_dir = base_path / "announce"

        for file_path in advisory_dir.glob("**/*"):
            if file_path.suffix not in [".yml", ".md"]:
                continue
            yield from parse_advisory(file_path, base_path)


def parse_advisory(file_path: Path, base_path: Path) -> Iterable[AdvisoryDataV2]:
    advisory_url = get_advisory_url(
        file=file_path,
        base_path=base_path,
        url="https://github.com/mozilla/foundation-security-advisories/blob/master/",
    )

    mfsa_id = mfsa_id_from_filename(file_path.name)
    if not mfsa_id:
        return []

    with open(file_path) as lines:
        if file_path.suffix == ".md":
            yield from parse_md_advisory(mfsa_id, lines, advisory_url)
        elif file_path.suffix == ".yml":
            yield from parse_yml_advisory(mfsa_id, lines, advisory_url)


def parse_yml_advisory(mfsa_id, lines, advisory_url) -> Iterable[AdvisoryDataV2]:
    data = yaml.safe_load(lines)

    affected_packages = list(parse_affected_packages(data.get("fixed_in") or []))
    reference = ReferenceV2(
        url=f"https://www.mozilla.org/en-US/security/advisories/{mfsa_id}",
    )
    severity = get_severity_from_impact(data.get("impact"), url=reference.url)
    date_published = data.get("announced")
    mfsa_summary = data.get("description", "")
    mfsa_summary = BeautifulSoup(mfsa_summary, features="lxml").get_text()

    advisories = data.get("advisories", {})

    if not advisories:
        yield AdvisoryDataV2(
            advisory_id=mfsa_id,
            aliases=[],
            summary=mfsa_summary,
            affected_packages=affected_packages,
            references_v2=[reference],
            severities=[severity],
            url=advisory_url,
            date_published=date_parser.parse(date_published) if date_published else None,
            original_advisory_text=json.dumps(data, indent=2, ensure_ascii=False),
        )

    for cve, advisory in advisories.items():
        if not is_cve(cve):
            continue

        advisory_summary = BeautifulSoup(
            advisory.get("description", ""), features="lxml"
        ).get_text()
        impact = advisory.get("impact", "")
        advisory_severity = get_severity_from_impact(impact, url=reference.url)

        yield AdvisoryDataV2(
            advisory_id=f"{mfsa_id}/{cve}",
            aliases=[cve],
            summary=mfsa_summary + "\n" + advisory_summary,
            affected_packages=affected_packages,
            references_v2=[reference],
            url=advisory_url,
            severities=[advisory_severity],
            date_published=date_parser.parse(date_published) if date_published else None,
            original_advisory_text=json.dumps(advisory, indent=2, ensure_ascii=False),
        )


def parse_md_advisory(mfsa_id, lines, advisory_url) -> Iterable[AdvisoryDataV2]:
    yamltext, mdtext = split_markdown_front_matter(lines.read())
    data = yaml.safe_load(yamltext)

    affected_packages = list(parse_affected_packages(data.get("fixed_in") or []))
    reference = ReferenceV2(
        url=f"https://www.mozilla.org/en-US/security/advisories/{mfsa_id}",
    )
    severity = get_severity_from_impact(data.get("impact"), url=reference.url)
    description = extract_description_from_html(mdtext)

    yield AdvisoryDataV2(
        advisory_id=mfsa_id,
        aliases=[],
        summary=description,
        affected_packages=affected_packages,
        references_v2=[reference],
        severities=[severity],
        url=advisory_url,
        date_published=date_parser.parse(data.get("announced")) if data.get("announced") else None,
        original_advisory_text=json.dumps(data, indent=2, ensure_ascii=False),
    )


def extract_description_from_html(md_text: str) -> str:
    html = markdown(md_text)
    soup = BeautifulSoup(html, features="lxml")
    h3tag = soup.find("h3", string=lambda s: s and s.lower() == "description")
    if not h3tag:
        return ""

    description_parts = []
    for sibling in h3tag.find_next_siblings():
        if sibling.name != "p":
            break
        description_parts.append(sibling.get_text())

    return "\n".join(description_parts).strip()


def parse_affected_packages(pkgs: list) -> Iterable[AffectedPackageV2]:
    for pkg in pkgs:
        if not pkg:
            continue

        name, _, version = pkg.rpartition(" ")
        if version.count(".") == 3:
            continue  # invalid SemVer
        try:
            fixed_version_range = GenericVersionRange.from_versions([version])
        except Exception:
            logger.debug(f"Invalid version '{version}' for package '{name}'")
            continue

        yield AffectedPackageV2(
            package=PackageURL(type="mozilla", name=name),
            fixed_version_range=fixed_version_range,
        )


def get_reference_and_severity(mfsa_id: str, impact: str) -> ReferenceV2:
    return ReferenceV2(
        url=f"https://www.mozilla.org/en-US/security/advisories/{mfsa_id}",
    )


def mfsa_id_from_filename(filename: str):
    match = MFSA_FILENAME_RE.search(filename)
    return f"mfsa{match.group(1)}" if match else None


def get_severity_from_impact(impact: str, url=None) -> VulnerabilitySeverity:
    """
    Extracts the severity from the impact string.
    """
    impact = (impact or "").lower()
    if impact == "moderate":
        impact = "medium"
    severities = ["critical", "high", "medium", "low", "none"]
    severity_value = "none"

    for level in severities:
        if level in impact:
            severity_value = level
            break

    return VulnerabilitySeverity(system=GENERIC, value=severity_value, url=url)
