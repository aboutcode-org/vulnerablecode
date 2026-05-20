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

from fetchcode.vcs import fetch_via_vcs
from packageurl.contrib.url2purl import url2purl

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.advisory import VCS_URLS_SUPPORTED_TYPES
from vulnerabilities.pipes.advisory import classify_patch_source
from vulnerabilities.utils import get_advisory_url


class VSCCollectorPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline to collect fix commits, pull requests, issues from List of git repositories.
    """

    pipeline_id = "vcs_collector_importer_v2"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        """Clone the repository."""
        self.repo_url = "git+https://github.com/aboutcode-data/vulnerablecode-vcs-collector"
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        return 0

    def collect_advisories_fix_commits(self):
        """
        Generate AdvisoryData objects for each vulnerability ID grouped with its related commits.
        """
        base_path = Path(self.vcs_response.dest_dir)
        advisory_dir = base_path / "data" / "fix-commits"
        for file in advisory_dir.rglob("*.json"):
            with open(file) as f:
                raw_data = json.load(f)
                vcs_url = raw_data["vcs_url"]
                purl = url2purl(vcs_url)
                if not purl or (purl.type not in VCS_URLS_SUPPORTED_TYPES):
                    self.log(f"Unsupported url2purl for git repo url: {vcs_url}")
                    continue
                vulnerabilities = raw_data.get("vulnerabilities", {})
                advisory_url = get_advisory_url(
                    file=file,
                    base_path=base_path,
                    url="https://github.com/aboutcode-data/vulnerablecode-vcs-collector/blob/main/",
                )

                for vuln_id, commits_data in vulnerabilities.items():
                    if not commits_data or not vuln_id:
                        continue

                    summary = ""
                    affected_packages = []
                    references = []
                    for commit_hash, commit_message in commits_data.items():
                        summary += f"{commit_hash}:{commit_message}\n"

                        affected_package = AffectedPackageV2(
                            package=purl,
                            fixed_by_commit_patches=[
                                PackageCommitPatchData(vcs_url=vcs_url, commit_hash=commit_hash)
                            ],
                        )
                        affected_packages.append(affected_package)

                    yield AdvisoryDataV2(
                        advisory_id=vuln_id,
                        summary=summary,
                        affected_packages=affected_packages,
                        references=references,
                        url=advisory_url,
                    )

    def collect_advisories_prs_and_issues(self):
        """
        Generating AdvisoryData objects from GitHub/Gitlab issues and PRs.
        """
        base_path = Path(self.vcs_response.dest_dir)
        advisory_dir = base_path / "data" / "issues-prs"
        for file in advisory_dir.rglob("*.json"):
            with open(file) as f:
                raw_data = json.load(f)
                vulnerabilities = raw_data.get("vulnerabilities", {})
                advisory_url = get_advisory_url(
                    file=file,
                    base_path=base_path,
                    url="https://github.com/aboutcode-data/vulnerablecode-vcs-collector/blob/main/",
                )

            for vuln_id, vul_data in vulnerabilities.items():
                references = [
                    ReferenceV2(reference_id=vuln_id, reference_type="Issues", url=url)
                    for url in vul_data["Issues"]
                ]
                references += [
                    ReferenceV2(reference_id=vuln_id, reference_type="PRs", url=url)
                    for url in vul_data["PRs"]
                ]
                yield AdvisoryDataV2(
                    advisory_id=vuln_id,
                    aliases=[],
                    references=references,
                    url=advisory_url,
                    original_advisory_text=json.dumps(raw_data, indent=2, ensure_ascii=False),
                )

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        yield from self.collect_advisories_fix_commits()
        yield from self.collect_advisories_prs_and_issues()

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
