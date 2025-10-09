#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path
from typing import Iterable

import saneyaml
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.maven import VersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import get_advisory_url


class ProjectKBPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    ProjectKB Importer Pipeline
    Collect advisory from ProjectKB data:
    - YAML statements: https://github.com/SAP/project-kb/blob/vulnerability-data/statements/*/*.yaml
    """

    pipeline_id = "project-kb_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/SAP/project-kb/blob/main/LICENSE.txt"
    repo_url = "git+https://github.com/SAP/project-kb@vulnerability-data"

    @classmethod
    def steps(cls):
        return (cls.clone_repo, cls.collect_and_store_advisories, cls.clean_downloads)

    def clone_repo(self):
        self.log("Processing ProjectKB advisory data...")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        base_path = Path(self.vcs_response.dest_dir) / "statements"
        count = sum(1 for _ in base_path.rglob("*.yaml"))
        self.log(f"Estimated advisories to process: {count}")
        return count

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        """Collect fix commits from YAML statements under /statements."""
        base_path = Path(self.vcs_response.dest_dir) / "statements"

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
                if text_content:
                    note_texts.append(text_content)
            description = "\n".join(note_texts)

            references = []
            for fix in yaml_data.get("fixes", []):
                for commit in fix.get("commits", []):
                    commit_id = commit.get("id")
                    repo_url = commit.get("repository")
                    if not commit_id or not repo_url:
                        continue

                    commit_url = repo_url.replace(".git", "") + "/commit/" + commit_id
                    ref = ReferenceV2.from_url(commit_url)
                    references.append(ref)

            affected_packages = []
            for artifact in yaml_data.get("artifacts", []):
                affected = artifact.get("affected")
                if not affected:
                    continue

                purl_str = artifact.get("id")
                purl = PackageURL.from_string(purl_str)

                affected_package = AffectedPackageV2(
                    package=PackageURL(type=purl.type, namespace=purl.namespace, name=purl.name),
                    fixed_version_range=VersionRange.from_version(purl.version),
                )
                affected_packages.append(affected_package)

            advisory_url = get_advisory_url(
                file=yaml_file,
                base_path=base_path,
                url="https://github.com/SAP/project-kb/blob/vulnerability-data/statements/",
            )

            yield AdvisoryData(
                advisory_id=vulnerability_id,
                aliases=[],
                summary=description or "",
                affected_packages=affected_packages,
                references_v2=references,
                url=advisory_url,
                original_advisory_text=json.dumps(yaml_data, indent=2, ensure_ascii=False),
            )

    def clean_downloads(self):
        """Remove the cloned repository from disk."""
        self.log("Removing cloned repository...")
        if self.vcs_response:
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup happens on pipeline failure."""
        self.clean_downloads()
