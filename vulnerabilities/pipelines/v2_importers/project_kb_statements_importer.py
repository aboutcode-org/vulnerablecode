#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import saneyaml
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.versions import InvalidVersion

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.advisory import append_patch_classifications
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import is_commit


class ProjectKBStatementsPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    ProjectKB Importer Pipeline
    Collect advisory from ProjectKB data:
    - YAML statements: https://github.com/SAP/project-kb/blob/vulnerability-data/statements/*/*.yaml
    """

    pipeline_id = "project-kb-statements_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/SAP/project-kb/blob/main/LICENSE.txt"
    repo_url = "git+https://github.com/SAP/project-kb@vulnerability-data"

    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log("Cloning ProjectKB Statements advisory data...")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        base_path = Path(self.vcs_response.dest_dir) / "statements"
        count = sum(1 for _ in base_path.rglob("*.yaml"))
        self.log(f"Estimated advisories to process: {count}")
        return count

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        self.log("Collecting fix commits from YAML statements under /statements....")
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
            references = []
            for note_entry in yaml_data.get("notes", []):
                text_content = note_entry.get("text")
                if not text_content:
                    continue
                note_texts.append(text_content)

                for link in note_entry.get("links", []):
                    ref = ReferenceV2(url=link)
                    references.append(ref)

            description = "\n".join(note_texts)
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

            purls_to_versions = defaultdict(lambda: [[], []])
            for artifact in yaml_data.get("artifacts", []):
                affected = artifact.get("affected")
                purl_str = artifact.get("id")

                try:
                    purl = PackageURL.from_string(purl_str)
                except ValueError:
                    self.log(f"Invalid PackageURL: {purl_str!r}")
                    continue

                version_range_class = RANGE_CLASS_BY_SCHEMES.get(purl.type)
                if not version_range_class:
                    continue

                base_purl = PackageURL(
                    type=purl.type,
                    namespace=purl.namespace,
                    name=purl.name,
                )

                if affected:
                    purls_to_versions[base_purl][0].append(purl.version)
                else:
                    purls_to_versions[base_purl][1].append(purl.version)

            for base_purl, (affected_versions, fixed_versions) in purls_to_versions.items():
                version_range_class = RANGE_CLASS_BY_SCHEMES.get(base_purl.type)

                affected_range = None
                fixed_range = None

                if affected_versions:
                    try:
                        affected_range = version_range_class.from_versions(affected_versions)
                    except InvalidVersion as e:
                        self.log(f"Invalid affected versions for {base_purl}: {e}")

                if fixed_versions:
                    try:
                        fixed_range = version_range_class.from_versions(fixed_versions)
                    except InvalidVersion as e:
                        self.log(f"Invalid fixed versions for {base_purl}: {e}")

                if affected_range or fixed_range:
                    pkg = AffectedPackageV2(
                        package=base_purl,
                        affected_version_range=affected_range,
                        fixed_version_range=fixed_range,
                    )
                    affected_packages.append(pkg)

            advisory_url = get_advisory_url(
                file=yaml_file,
                base_path=base_path,
                url="https://github.com/SAP/project-kb/blob/vulnerability-data/statements/",
            )

            yield AdvisoryDataV2(
                advisory_id=vulnerability_id,
                summary=description,
                affected_packages=affected_packages,
                references=references,
                patches=patches,
                url=advisory_url,
            )

    def clean_downloads(self):
        """Remove the cloned repository from disk."""
        self.log("Removing cloned repository...")

        if self.vcs_response:
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup happens on pipeline failure."""
        self.clean_downloads()
