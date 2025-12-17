#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import csv
from pathlib import Path
from typing import Iterable

import saneyaml
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.versions import InvalidVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.advisory import append_patch_classifications
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import is_commit


class ProjectKBPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    ProjectKB Importer Pipeline
    Collect advisory from ProjectKB data:
    - YAML statements: https://github.com/SAP/project-kb/blob/vulnerability-data/statements/*/*.yaml
    - CSV database https://github.com/SAP/project-kb/blob/main/MSR2019/dataset/vulas_db_msr2019_release.csv
    """

    pipeline_id = "project-kb_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/SAP/project-kb/blob/main/LICENSE.txt"
    main_branch = "git+https://github.com/SAP/project-kb"
    vuln_data_branch = "git+https://github.com/SAP/project-kb@vulnerability-data"

    @classmethod
    def steps(cls):
        return (cls.clone_repo, cls.collect_and_store_advisories, cls.clean_downloads)

    def clone_repo(self):
        self.log("Cloning ProjectKB advisory data...")
        self.main_branch_vcs = fetch_via_vcs(self.main_branch)
        self.vuln_data_branch_vcs = fetch_via_vcs(self.vuln_data_branch)

    def advisories_count(self):
        base_path = Path(self.vuln_data_branch_vcs.dest_dir) / "statements"
        csv_path = (
            Path(self.main_branch_vcs.dest_dir) / "MSR2019/dataset/vulas_db_msr2019_release.csv"
        )

        count_files = sum(1 for _ in base_path.rglob("*.yaml"))
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)
            count_rows = sum(1 for _ in reader)

        count = count_files + count_rows
        self.log(f"Estimated advisories to process: {count}")
        return count

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        self.log("Collecting fix commits from YAML statements under /statements....")
        base_path = Path(self.vuln_data_branch_vcs.dest_dir) / "statements"

        for yaml_file in base_path.rglob("*.yaml"):
            if yaml_file.name != "statement.yaml":
                continue

            with open(yaml_file, encoding="utf-8") as f:
                yaml_data = saneyaml.load(f)

            vulnerability_id = yaml_data.get("vulnerability_id")
            if not vulnerability_id:
                continue

            note_texts = []
            for note_entry in yaml_data.get("notes", []):
                text_content = note_entry.get("text")
                if not text_content:
                    continue
                note_texts.append(text_content)
            description = "\n".join(note_texts)

            references = []
            affected_packages = []
            patches = []
            for fix in yaml_data.get("fixes", []):
                for commit in fix.get("commits", []):
                    commit_hash = commit.get("id")
                    if not is_commit(commit_hash):
                        commit_hash = None

                    vcs_url = commit.get("repository")
                    append_patch_classifications(
                        url=vcs_url,
                        commit_hash=commit_hash,
                        patch_text=None,
                        affected_packages=affected_packages,
                        references=references,
                        patches=patches,
                    )

            for artifact in yaml_data.get("artifacts", []):
                affected = artifact.get("affected")
                if not affected:
                    continue

                purl_str = artifact.get("id")
                purl = PackageURL.from_string(purl_str)

                try:
                    version_range_class = RANGE_CLASS_BY_SCHEMES.get(purl.type)
                    version_class = (
                        version_range_class.version_class if version_range_class else None
                    )
                    version_range = version_class(purl.version)
                except InvalidVersion:
                    self.log(f"Invalid Version: {purl.version!r} for purl type: {purl.type!r}")
                    continue

                affected_package = AffectedPackageV2(
                    package=PackageURL(type=purl.type, namespace=purl.namespace, name=purl.name),
                    fixed_version_range=version_range if not affected else None,
                    affected_version_range=version_range if affected else None,
                )
                affected_packages.append(affected_package)

            advisory_url = get_advisory_url(
                file=yaml_file,
                base_path=base_path,
                url="https://github.com/SAP/project-kb/blob/vulnerability-data/statements/",
            )

            yield AdvisoryData(
                advisory_id=vulnerability_id,
                summary=description,
                affected_packages=affected_packages,
                references_v2=references,
                patches=patches,
                url=advisory_url,
            )

        self.log("Collecting fix commits from ProjectKB ( vulas_db_msr2019_release )...")
        csv_path = (
            Path(self.main_branch_vcs.dest_dir) / "MSR2019/dataset/vulas_db_msr2019_release.csv"
        )

        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # skip header
            rows = [r for r in reader if len(r) == 4 and r[0]]  # vuln_id, vcs_url, commit_hash, poc

        for vuln_id, vcs_url, commit_hash, _ in rows:
            if not vuln_id or not vcs_url or not commit_hash:
                continue

            patches = []
            affected_packages = []
            references = []
            append_patch_classifications(
                url=vcs_url,
                commit_hash=commit_hash,
                patch_text=None,
                affected_packages=affected_packages,
                references=references,
                patches=patches,
            )

            yield AdvisoryData(
                advisory_id=vuln_id,
                affected_packages=affected_packages,
                patches=patches,
                references_v2=references,
                url="https://github.com/SAP/project-kb/blob/main/MSR2019/dataset/vulas_db_msr2019_release.csv",
            )

    def clean_downloads(self):
        """Remove the cloned repository from disk."""
        self.log("Removing cloned repository...")
        if self.main_branch_vcs:
            self.main_branch_vcs.delete()

        if self.vuln_data_branch_vcs:
            self.vuln_data_branch_vcs.delete()

    def on_failure(self):
        """Ensure cleanup happens on pipeline failure."""
        self.clean_downloads()
