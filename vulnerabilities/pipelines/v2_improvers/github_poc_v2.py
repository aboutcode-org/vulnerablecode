#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from github import Github
from vulnerabilities.models import AdvisoryAlias, AdvisoryExploit, AdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerablecode.settings import env

GITHUB_TOKEN = env.str("GITHUB_TOKEN")

class GitHubPocImproverPipeline(VulnerableCodePipeline):
    """
    Pipeline to collect GitHub PoCs for vulnerabilities.
    """

    pipeline_id = "collect_poc"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.github = Github(login_or_token=GITHUB_TOKEN)

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_poc_results,
        )

    def search_github_pocs(self, cve_id):
        """Search for PoCs on GitHub for each CVE"""
        self.log(f"Searching GitHub for PoCs for {cve_id}")

        query = f'"{cve_id}" PoC OR exploit OR "proof of concept"'
        return self.github.search_repositories(query)

    def collect_and_store_poc_results(self):
        """Store PoC results in the database"""
        self.log("Storing PoC results in database...")
        for advisory_alias in reversed(AdvisoryAlias.objects.filter(alias__startswith="CVE")):
            repositories = self.search_github_pocs(advisory_alias.alias)

            if not repositories:
                continue

            for repository in repositories:
                for advisory in advisory_alias.advisories.all():
                    AdvisoryExploit.objects.update_or_create(
                        advisory=advisory,
                        data_source="GitHub POC",
                        defaults={
                            "description": repository.description,
                            "notes": str(repository),
                            "platform": "github",
                        },
                    )
                    print(repository)