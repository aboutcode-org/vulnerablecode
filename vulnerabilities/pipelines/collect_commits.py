#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from aboutcode.pipeline import LoopProgress

from vulnerabilities.models import CodeFix
from vulnerabilities.models import Package
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import normalize_purl


class CollectFixCommitsPipeline(VulnerableCodePipeline):
    """
    Improver pipeline to scout References and create CodeFix entries.
    """

    pipeline_id = "collect_fix_commits"
    license_expression = None

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_fix_commits,)

    def collect_and_store_fix_commits(self):
        references = VulnerabilityReference.objects.prefetch_related("vulnerabilities").distinct()

        self.log(f"Processing {references.count():,d} references to collect fix commits.")

        created_fix_count = 0
        progress = LoopProgress(total_iterations=references.count(), logger=self.log)
        for reference in progress.iter(references.paginated(per_page=500)):
            for vulnerability in reference.vulnerabilities.all():
                package_urls = self.extract_package_urls(reference)
                commit_id = self.extract_commit_id(reference.url)

                if commit_id and package_urls:
                    for purl in package_urls:
                        normalized_purl = normalize_purl(purl)
                        package = self.get_or_create_package(normalized_purl)
                        codefix = self.create_codefix_entry(
                            vulnerability=vulnerability,
                            package=package,
                            commit_id=commit_id,
                            reference=reference.url,
                        )
                        if codefix:
                            created_fix_count += 1

        self.log(f"Successfully created {created_fix_count:,d} CodeFix entries.")

    def extract_package_urls(self, reference):
        """
        Extract Package URLs from a reference.
        Returns a list of Package URLs inferred from the reference.
        """
        urls = []
        if "github" in reference.url:
            parts = reference.url.split("/")
            if len(parts) >= 5:
                namespace = parts[-3]
                name = parts[-2]
                commit = parts[-1]
                if commit:
                    urls.append(f"pkg:github/{namespace}/{name}@{commit}")
        return urls

    def extract_commit_id(self, url):
        """
        Extract a commit ID from a URL, if available.
        """
        if "github" in url:
            parts = url.split("/")
            return parts[-1] if len(parts) > 0 else None
        return None

    def get_or_create_package(self, purl):
        """
        Get or create a Package object from a Package URL.
        """
        try:
            package, _ = Package.objects.get_or_create_from_purl(purl)
            return package
        except Exception as e:
            self.log(f"Error creating package from purl {purl}: {e}")
            return None

    def create_codefix_entry(self, vulnerability, package, commit_id, reference):
        """
        Create a CodeFix entry associated with the given vulnerability and package.
        """
        try:
            codefix, created = CodeFix.objects.get_or_create(
                base_version=package,
                defaults={
                    "commits": [commit_id],
                    "references": [reference],
                },
            )
            if created:
                codefix.vulnerabilities.add(vulnerability)
                codefix.save()
            return codefix
        except Exception as e:
            self.log(f"Error creating CodeFix entry: {e}")
            return None
