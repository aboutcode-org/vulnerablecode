#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from pathlib import Path

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import PatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.advisory import classify_patch_source
from vulnerabilities.utils import commit_regex
from vulnerabilities.utils import cve_regex
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import is_commit


class LinuxKernelPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline to collect Linux Kernel Pipeline:
    """

    pipeline_id = "linux_kernel_cves_fix_commits"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/nluedtke/linux_kernel_cves/blob/master/LICENSE"
    importer_name = "linux_kernel_cves_fix_commits"
    qualified_name = "linux_kernel_cves_fix_commits"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def advisories_count(self):
        root = Path(self.vcs_response.dest_dir)
        return sum(1 for _ in root.rglob("data/*.txt"))

    def clone(self):
        self.repo_url = "git+https://github.com/nluedtke/linux_kernel_cves"
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_advisories(self):
        self.log(f"Processing linux kernel fix commits.")
        base_path = Path(self.vcs_response.dest_dir) / "data"
        for file_path in base_path.rglob("*.txt"):
            if "_CVEs.txt" in file_path.name:
                continue

            if "_security.txt" in file_path.name:
                patches = []
                affected_packages = []
                references = []
                for vulnerability_id, commit_hash in self.parse_commits_file(file_path):
                    patch_url = f"https://github.com/torvalds/linux/commit/{commit_hash}"
                    if not commit_hash:
                        continue

                    base_purl, patch_objs = classify_patch_source(
                        url=patch_url,
                        commit_hash=commit_hash,
                        patch_text=None,
                    )

                    for patch_obj in patch_objs:
                        if isinstance(patch_obj, PackageCommitPatchData):
                            fixed_commit = patch_obj
                            affected_package = AffectedPackageV2(
                                package=base_purl,
                                fixed_by_commit_patches=[fixed_commit],
                            )
                            affected_packages.append(affected_package)
                        elif isinstance(patch_obj, PatchData):
                            patches.append(patch_obj)
                        elif isinstance(patch_obj, ReferenceV2):
                            references.append(patch_obj)

                    advisory_url = get_advisory_url(
                        file=file_path,
                        base_path=self.vcs_response.dest_dir,
                        url="https://github.com/nluedtke/linux_kernel_cves/blob/master/",
                    )

                    yield AdvisoryData(
                        advisory_id=vulnerability_id,
                        references_v2=references,
                        affected_packages=affected_packages,
                        patches=patches,
                        url=advisory_url,
                    )

    def parse_commits_file(self, file_path):
        """Extract CVE-ID and commit hashes from a text file"""
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(":", 2)

                if len(parts) < 2:
                    continue

                cve_part = parts[0]
                commit_part = parts[1]

                cve_match = cve_regex.search(cve_part)
                if not cve_match:
                    continue

                cve = cve_match.group(0)

                sha1_match = commit_regex.search(commit_part)
                commit_hash = sha1_match.group(0) if sha1_match else None

                if not commit_hash or not is_commit(commit_hash):
                    continue

                yield cve, commit_hash

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
