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

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import get_advisory_url

logger = logging.getLogger(__name__)


class OpenSSFMaliciousImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    OpenSSF Malicious Packages Importer Pipeline

    Collect advisories for malicious packages from the OpenSSF malicious-packages
    repository. This includes typosquatting, dependency confusion, and other
    malicious packages discovered in npm, PyPI, RubyGems, and other ecosystems.

    See: https://github.com/ossf/malicious-packages
    """

    pipeline_id = "openssf_malicious_importer"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/ossf/malicious-packages/blob/main/LICENSE"
    repo_url = "git+https://github.com/ossf/malicious-packages/"

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
        advisory_dir = Path(self.vcs_response.dest_dir) / "osv" / "malicious"
        return sum(1 for _ in advisory_dir.rglob("*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        from vulnerabilities.importers.osv import parse_advisory_data_v2

        # Ecosystems supported by both OpenSSF malicious-packages and VulnerableCode
        # Mapping: OSV ecosystem name -> purl type
        supported_ecosystems = [
            "pypi",      # Python packages
            "npm",       # JavaScript/Node.js packages
            "cargo",     # Rust packages (crates.io)
            "gem",       # Ruby packages (rubygems)
            "maven",     # Java packages
            "nuget",     # .NET packages
            "golang",    # Go packages
        ]

        base_path = Path(self.vcs_response.dest_dir)
        advisory_dir = base_path / "osv" / "malicious"

        for file in advisory_dir.rglob("*.json"):
            try:
                with open(file) as f:
                    raw_data = json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON from {file}: {e}")
                continue

            advisory_url = get_advisory_url(
                file=file,
                base_path=base_path,
                url="https://github.com/ossf/malicious-packages/blob/main/",
            )
            advisory_text = file.read_text()

            advisory = parse_advisory_data_v2(
                raw_data=raw_data,
                supported_ecosystems=supported_ecosystems,
                advisory_url=advisory_url,
                advisory_text=advisory_text,
            )

            if advisory:
                yield advisory

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
