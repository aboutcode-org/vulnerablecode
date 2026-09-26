# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import gzip
from pathlib import Path
from typing import Iterable

from aboutcode.pipeline import LoopProgress
from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipelines.v2_importers.epss_importer_v2 import parse_epss_advisories


class EPSSImporterHistoryPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Exploit Prediction Scoring System (EPSS) History Importer"""

    pipeline_id = "epss_importer_v2"
    spdx_license_expression = "unknown"
    importer_name = "EPSS History Importer"
    datasource_id = "epss"
    repo_url = "https://github.com/empiricalsec/epss_scores"

    exclude_from_package_todo = True
    run_once = True
    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_up,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(f"git+{self.repo_url}")

    def advisories_count(self) -> int:
        advisory_dir = Path(self.vcs_response.dest_dir)
        return sum(1 for f in advisory_dir.rglob("*.csv.gz") if "beta_scores" not in f.parts)

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        advisory_dir = Path(self.vcs_response.dest_dir)
        self.log(f"Scanning for EPSS CSV.gz files in: {advisory_dir}")

        epss_files = sorted(
            (f for f in advisory_dir.rglob("*.csv.gz") if "beta_scores" not in f.parts),
            key=lambda f: f.name,
        )
        self.log(f"Found {len(epss_files)} EPSS files to process.")

        if epss_files:
            self.log(f"Processing EPSS data from {epss_files[0].name} " f"to {epss_files[-1].name}")

        progress = LoopProgress(
            total_iterations=len(epss_files),
            logger=self.log,
        )

        for file_path in progress.iter(epss_files):
            relative_path = file_path.relative_to(advisory_dir)
            advisory_url = f"{self.repo_url}/blob/main/{relative_path.as_posix()}"

            try:
                with gzip.open(file_path, mode="rt", encoding="utf-8") as f:
                    lines = f.readlines()
            except (OSError, gzip.BadGzipFile) as e:
                self.log(f"Failed to read {file_path}: {e}. Skipping this file.")
                continue

            yield from parse_epss_advisories(
                lines=lines, advisory_url=advisory_url, logger=self.log
            )

        self.log(f"Finished processing all {len(epss_files)} EPSS files.")

    def clean_up(self):
        if getattr(self, "vcs_response", None):
            self.vcs_response.delete()
            self.log("Successfully removed cloned EPSS repository")

    def on_failure(self):
        self.log("EPSS importer pipeline failed, running cleanup")
        self.clean_up()
