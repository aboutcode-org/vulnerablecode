#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
import shutil
import tempfile
from collections import defaultdict

from git import Repo
from packageurl.contrib.url2purl import url2purl

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2


class CollectVCSFixCommitPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline to collect fix commits from any git repository.
    """

    repo_url: str
    patterns: list[str] = [
        r"\bCVE-\d{4}-\d{4,19}\b",
        r"GHSA-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}-[2-9cfghjmpqrvwx]{4}",
    ]

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        """Clone the repository."""
        self.repo = Repo.clone_from(
            url=self.repo_url,
            to_path=tempfile.mkdtemp(),
            bare=True,
            no_checkout=True,
            multi_options=["--filter=blob:none"],
        )

    def advisories_count(self) -> int:
        return 0

    def extract_vulnerability_id(self, commit) -> list[str]:
        """
        Extract vulnerability id from a commit message.
        Returns a list of matched vulnerability IDs
        """
        matches = []
        for pattern in self.patterns:
            found = re.findall(pattern, commit.message, flags=re.IGNORECASE)
            matches.extend(found)
        return matches

    def collect_fix_commits(self):
        """
        Iterate through repository commits and group them by vulnerability identifiers.
        return a list with (vuln_id, [(commit_id, commit_message)]).
        """
        self.log("Processing git repository fix commits (grouped by vulnerability IDs).")

        grouped_commits = defaultdict(list)
        for commit in self.repo.iter_commits("--all"):
            matched_ids = self.extract_vulnerability_id(commit)
            if not matched_ids:
                continue

            commit_id = commit.hexsha
            commit_message = commit.message.strip()

            for vuln_id in matched_ids:
                grouped_commits[vuln_id].append((commit_id, commit_message))

        self.log(f"Found {len(grouped_commits)} vulnerabilities with related commits.")
        self.log("Finished processing all commits.")
        return grouped_commits

    def collect_advisories(self):
        """
        Generate AdvisoryData objects for each vulnerability ID grouped with its related commits.
        """
        self.log("Generating AdvisoryData objects from grouped commits.")
        grouped_commits = self.collect_fix_commits()
        purl = url2purl(self.repo_url)
        for vuln_id, commits_data in grouped_commits.items():

            if not commits_data or not vuln_id:
                continue

            summary = ""
            commit_hash_set = set()
            for commit_hash, commit_message in commits_data:
                summary += f"{commit_hash}:{commit_message}\n"
                commit_hash_set.add(commit_hash)

            affected_packages = [
                AffectedPackageV2(
                    package=purl,
                    fixed_by_commit_patches=[
                        PackageCommitPatchData(vcs_url=self.repo_url, commit_hash=commit_hash)
                        for commit_hash in commit_hash_set
                    ],
                )
            ]

            yield AdvisoryData(
                advisory_id=vuln_id,
                summary=summary,
                affected_packages=affected_packages,
                url=self.repo_url,
            )

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        self.log("Cleaning up local repository resources.")
        if hasattr(self, "repo") and self.repo.working_dir:
            shutil.rmtree(path=self.repo.working_dir)

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
