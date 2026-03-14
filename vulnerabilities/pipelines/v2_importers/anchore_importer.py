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
from pathlib import Path
from typing import Iterable

from dateutil import parser as dateparser
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipelines.v2_importers.nvd_importer import is_related_to_hardware

logger = logging.getLogger(__name__)


class AnchoreImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Import NVD data overrides from Anchore.

    Anchore provides CPE configurations for CVEs not yet analyzed by NVD,
    as well as corrections to existing NVD CPE data.
    See https://github.com/anchore/nvd-data-overrides
    """

    pipeline_id = "anchore_importer_v2"
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/anchore/nvd-data-overrides/blob/main/LICENSE"
    repo_url = "git+https://github.com/anchore/nvd-data-overrides.git"

    precedence = 50

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
        self.data_path = Path(self.vcs_response.dest_dir) / "data"

    def advisories_count(self):
        return sum(1 for _ in self.data_path.glob("**/CVE-*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for advisory_file in sorted(self.data_path.glob("**/CVE-*.json")):
            advisory = self.parse_advisory(advisory_file)
            if advisory:
                yield advisory

    def parse_advisory(self, file: Path):
        try:
            raw_data = json.loads(file.read_text())
        except json.JSONDecodeError:
            logger.error(f"Failed to parse JSON: {file}")
            return None

        annotation = raw_data.get("_annotation") or {}
        cve_id = annotation.get("cve_id")
        if not cve_id:
            return None

        cpe_configurations = raw_data.get("cve", {}).get("configurations") or []
        cpes = extract_cpes(cpe_configurations)

        if all(is_related_to_hardware(cpe) for cpe in cpes) and cpes:
            return None

        references = []
        for cpe in cpes:
            cpe_url = (
                "https://nvd.nist.gov/vuln/search/results"
                f"?adv_search=true&isCpeNameSearch=true&query={cpe}"
            )
            references.append(ReferenceV2(reference_id=cpe, url=cpe_url))

        references.append(
            ReferenceV2(
                reference_id=cve_id,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )

        for ref_url in annotation.get("references") or []:
            if ref_url and ref_url.startswith("http"):
                references.append(ReferenceV2(url=ref_url))

        date_published = None
        published_str = annotation.get("published")
        if published_str:
            date_published = dateparser.parse(published_str)

        summary = annotation.get("description") or ""

        advisory_url = (
            "https://github.com/anchore/nvd-data-overrides/blob/main/"
            f"data/{file.parent.name}/{file.name}"
        )

        return AdvisoryDataV2(
            advisory_id=cve_id,
            aliases=[],
            summary=summary,
            references=references,
            date_published=date_published,
            weaknesses=[],
            url=advisory_url,
            original_advisory_text=json.dumps(raw_data, indent=2, ensure_ascii=False),
        )

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def extract_cpes(configurations):
    """
    Return a list of unique CPE strings from NVD-format CPE configurations.

    >>> extract_cpes([{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "vulnerable": True}], "operator": "OR", "negate": False}]}])
    ['cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*']
    """
    cpes = []
    for config in configurations:
        for node in config.get("nodes") or []:
            for cpe_data in node.get("cpeMatch") or []:
                cpe = cpe_data.get("criteria")
                if cpe and cpe not in cpes:
                    cpes.append(cpe)
    return cpes
