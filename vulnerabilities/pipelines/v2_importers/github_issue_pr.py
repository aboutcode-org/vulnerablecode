#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
from collections import defaultdict

from github import Github

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerablecode.settings import env

GITHUB_TOKEN = env.str("GITHUB_TOKEN")


class GithubPipelineIssuePR(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline to collect GitHub issues and PRs related to vulnerabilities.
    """

    pipeline_id = "collect_issues_pr"

    @classmethod
    def steps(cls):
        return (
            cls.fetch_entries,
            cls.collect_and_store_advisories,
        )

    def fetch_entries(self):
        """Clone the repository."""
        self.repo_url = "https://github.com/torvalds/linux"
        repo_name = "django/django"

        g = Github(login_or_token=GITHUB_TOKEN)

        base_query = f"repo:{repo_name} (CVE OR PYSEC OR GHSA)"
        self.issues = g.search_issues(f"{base_query} is:issue")
        self.pull_requestes = g.search_issues(f"{base_query} is:pr")

    def advisories_count(self) -> int:
        """
        Return total number of advisories discovered (issues + PRs).
        """
        return self.issues.totalCount + self.pull_requestes.totalCount

    def collect_issues_and_prs(self):
        """
        Group issues and PRs by vulnerability identifiers (like CVE-xxxx-yyyy).
        Returns a dict mapping vuln_id -> [(type, html_url)].
        """
        self.log("Grouping GitHub issues and PRs by vulnerability identifiers.")

        grouped_items = defaultdict(list)
        pattern = re.compile(r"(CVE-\d{4}-\d+|PYSEC-\d{4}-\d+|GHSA-[\w-]+)", re.IGNORECASE)

        for issue in self.issues:
            matches = pattern.findall(issue.title + " " + (issue.body or ""))
            for match in matches:
                grouped_items[match].append(("Issue", issue.html_url))

        for pr in self.pull_requestes:
            matches = pattern.findall(pr.title + " " + (pr.body or ""))
            for match in matches:
                grouped_items[match].append(("PR", pr.html_url))

        self.log(f"Grouped {len(grouped_items)} unique vulnerability identifiers.")
        return grouped_items

    def collect_advisories(self):
        """
        Generate AdvisoryData objects for each vulnerability ID grouped with its related GitHub issues and PRs.
        """
        self.log("Generating AdvisoryData objects from GitHub issues and PRs.")
        grouped_data = self.collect_issues_and_prs()

        for vuln_id, refs in grouped_data.items():
            references = [ReferenceV2(reference_id=ref_id, url=url) for ref_id, url in refs]

            yield AdvisoryData(
                advisory_id=vuln_id,
                aliases=[vuln_id],
                references_v2=references,
                url=self.repo_url,
            )
