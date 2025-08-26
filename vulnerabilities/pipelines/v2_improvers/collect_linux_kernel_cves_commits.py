#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import re
from pathlib import Path

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import CodeFixV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import cve_regex


class CollectFixCommitLinuxKernelPipeline(VulnerableCodePipeline):
    """
    Pipeline to collect fix commits from Linux Kernel:
    """

    pipeline_id = "linux_kernel_cves_fix_commits"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/quarkslab/aosp_dataset/blob/master/LICENSE"
    importer_name = "linux_kernel_cves_fix_commits"
    qualified_name = "linux_kernel_cves_fix_commits"
    repo_url = "git+https://github.com/nluedtke/linux_kernel_cves"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_fix_commits,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_fix_commits(self):
        self.log(f"Processing aosp_dataset fix commits.")
        base_path = Path(self.vcs_response.dest_dir) / "data"
        for file_path in base_path.rglob("*.txt"):
            if "_CVEs.txt" in file_path.name:
                continue

            if "_security.txt" in file_path.name:
                for vulnerability_id, commit_hash in self.parse_commits_file(file_path):

                    kernel_urls = [
                        f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/{commit_hash}",
                        f"https://github.com/torvalds/linux/commit/{commit_hash}",
                    ]

                    if not (vulnerability_id and commit_hash):
                        continue

                    try:
                        advisories = AdvisoryV2.objects.filter(
                            advisory_id__iendswith=vulnerability_id
                        )
                    except AdvisoryV2.DoesNotExist:
                        self.log(f"Can't find vulnerability_id: {vulnerability_id}")
                        continue

                    for advisory in advisories:
                        for impact in advisory.impacted_packages.all():
                            for package in impact.affecting_packages.all():
                                code_fix, created = CodeFixV2.objects.get_or_create(
                                    commits=[kernel_urls],
                                    advisory=advisory,
                                    affected_package=package,
                                )

                                if created:
                                    self.log(
                                        f"Created CodeFix entry for vulnerability_id: {vulnerability_id} with VCS URL {kernel_urls}"
                                    )

    def parse_commits_file(self, file_path):
        sha1_pattern = re.compile(r"\b[a-f0-9]{40}\b")

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                cve_match = cve_regex.search(line)
                cve = cve_match.group(1) if cve_match else None

                sha1_match = sha1_pattern.search(line)
                commit_hash = sha1_match.group(0) if sha1_match else None
                yield cve, commit_hash

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
