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

import dateparser
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import CVSSV2
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import CVSSV31
from vulnerabilities.severity_systems import CVSSV4
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import get_cwe_id

logger = logging.getLogger(__name__)

# Map CSAF CVSS version strings to the scoring system objects used in VulnerableCode.
CSAF_CVSS_SCORING_SYSTEMS = {
    "2.0": CVSSV2,
    "3.0": CVSSV3,
    "3.1": CVSSV31,
    "4.0": CVSSV4,
}

CISAGOV_CSAF_BASE_URL = "https://github.com/cisagov/CSAF/blob/develop/"


class CISAGOVCSAFImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    CISAGOV CSAF Importer Pipeline

    This pipeline imports CSAF 2.0 security advisories published by CISA at
    https://github.com/cisagov/CSAF. Each advisory is a JSON file following
    the OASIS CSAF 2.0 standard and may contain one or more CVEs with CVSS
    scores, CWE IDs, and product information.
    """

    pipeline_id = "cisagov_csaf_importer"
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/cisagov/CSAF/blob/develop/LICENSE"
    repo_url = "git+https://github.com/cisagov/CSAF.git"

    precedence = 100

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

    def advisories_count(self):
        base_path = Path(self.vcs_response.dest_dir)
        return sum(1 for _ in base_path.glob("csaf_files/**/*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        base_path = Path(self.vcs_response.dest_dir)
        for file_path in sorted(base_path.glob("csaf_files/**/*.json")):
            try:
                with open(file_path, encoding="utf-8") as f:
                    raw_data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logger.error(f"Failed to read {file_path}: {e}")
                continue

            advisory_url = get_advisory_url(
                file=file_path,
                base_path=base_path,
                url=CISAGOV_CSAF_BASE_URL + "csaf_files/",
            )

            yield from parse_csaf_advisory(raw_data, advisory_url)

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def parse_csaf_advisory(raw_data: dict, advisory_url: str) -> Iterable[AdvisoryDataV2]:
    """
    Parse a CSAF 2.0 advisory document and yield one AdvisoryDataV2 per CVE
    found in the vulnerabilities list.

    A single CSAF file may describe multiple CVEs, so this function yields
    multiple AdvisoryDataV2 objects when that is the case.
    """
    document = raw_data.get("document", {})
    tracking = document.get("tracking", {})
    document_id = tracking.get("id", "")

    date_published = None
    release_date_str = tracking.get("initial_release_date")
    if release_date_str:
        date_published = dateparser.parse(
            release_date_str,
            settings={
                "TIMEZONE": "UTC",
                "RETURN_AS_TIMEZONE_AWARE": True,
                "TO_TIMEZONE": "UTC",
            },
        )

    document_summary = ""
    for note in document.get("notes", []):
        if note.get("category") == "summary":
            document_summary = note.get("text", "")
            break

    # Build a mapping of CSAF product ID -> product name for lookup.
    product_id_to_name = build_product_id_map(raw_data.get("product_tree", {}))

    # The document-level references (e.g. the self-reference link).
    document_references = []
    for ref in document.get("references", []):
        url = ref.get("url")
        if url:
            document_references.append(ReferenceV2(url=url))

    vulnerabilities = raw_data.get("vulnerabilities", [])
    if not vulnerabilities:
        return

    for vuln in vulnerabilities:
        cve_id = vuln.get("cve")
        if not cve_id:
            continue

        # Use the vulnerability-level title as a summary if available,
        # otherwise fall back to the document-level summary.
        vuln_summary = ""
        for note in vuln.get("notes", []):
            if note.get("category") == "summary":
                vuln_summary = note.get("text", "")
                break
        summary = vuln_summary or document_summary

        # CWE weakness
        weaknesses = []
        cwe_data = vuln.get("cwe", {})
        if cwe_data and cwe_data.get("id"):
            try:
                weaknesses.append(get_cwe_id(cwe_data["id"]))
            except Exception:
                pass

        # CVSS scores
        severities = []
        for score_entry in vuln.get("scores", []):
            for key, scoring_system in [
                ("cvss_v2", CVSSV2),
                ("cvss_v3", None),
                ("cvss_v4", CVSSV4),
            ]:
                score_data = score_entry.get(key)
                if not score_data:
                    continue

                vector_string = score_data.get("vectorString", "")
                base_score = score_data.get("baseScore")

                if key == "cvss_v3":
                    version = score_data.get("version", "")
                    scoring_system = CSAF_CVSS_SCORING_SYSTEMS.get(version, CVSSV31)

                if base_score is not None and vector_string:
                    severities.append(
                        VulnerabilitySeverity(
                            system=scoring_system,
                            value=str(base_score),
                            scoring_elements=vector_string,
                        )
                    )

        # References: combine document references with vulnerability-level references.
        references = list(document_references)
        for ref in vuln.get("references", []):
            url = ref.get("url")
            if url:
                references.append(ReferenceV2(url=url))

        # Use a date from the vulnerability if available (e.g. release_date).
        vuln_date = None
        vuln_release_str = vuln.get("release_date")
        if vuln_release_str:
            vuln_date = dateparser.parse(
                vuln_release_str,
                settings={
                    "TIMEZONE": "UTC",
                    "RETURN_AS_TIMEZONE_AWARE": True,
                    "TO_TIMEZONE": "UTC",
                },
            )
        effective_date = vuln_date or date_published

        # Use the document tracking ID as the advisory ID. When a file covers
        # multiple CVEs the document-level ID is still the canonical identifier
        # for this CISA advisory; the CVE becomes an alias.
        advisory_id = document_id or cve_id
        aliases = [cve_id] if advisory_id != cve_id else []

        yield AdvisoryDataV2(
            advisory_id=advisory_id,
            aliases=aliases,
            summary=summary,
            references=references,
            severities=severities,
            weaknesses=weaknesses,
            date_published=effective_date,
            url=advisory_url,
            original_advisory_text=json.dumps(raw_data, indent=2, ensure_ascii=False),
        )


def build_product_id_map(product_tree: dict) -> dict:
    """
    Walk the product_tree branches and relationships to build a flat mapping of
    CSAF product_id -> product name string.

    This is used internally when future enhancements need to resolve product IDs
    to names (e.g. for package matching).
    """
    product_map = {}
    _walk_branches(product_tree.get("branches", []), product_map)

    for rel in product_tree.get("relationships", []):
        fpn = rel.get("full_product_name", {})
        pid = fpn.get("product_id")
        name = fpn.get("name")
        if pid and name:
            product_map[pid] = name

    return product_map


def _walk_branches(branches: list, product_map: dict) -> None:
    """
    Recursively descend through CSAF product_tree branch nodes and collect
    product_id -> name mappings for leaf nodes that have a ``product`` key.
    """
    for branch in branches:
        product = branch.get("product", {})
        pid = product.get("product_id")
        name = product.get("name")
        if pid and name:
            product_map[pid] = name
        child_branches = branch.get("branches", [])
        if child_branches:
            _walk_branches(child_branches, product_map)
