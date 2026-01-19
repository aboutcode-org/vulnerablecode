#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

import dateparser
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.versions import InvalidVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import logger
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import build_description


class GlibcImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline to collect glibc advisories:
    """

    pipeline_id = "glibc_importer_v2"
    spdx_license_expression = "LGPL-2.1-only"
    license_url = "https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=LICENSES"
    repo_url = "git+https://sourceware.org/git/glibc.git"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        root = Path(self.vcs_response.dest_dir) / "advisories"
        return sum(1 for _ in root.rglob("*"))

    def collect_advisories(self):
        base_path = Path(self.vcs_response.dest_dir) / "advisories"
        for file_path in base_path.rglob("*"):
            if not file_path.name.startswith("GLIBC-SA"):
                continue

            with open(file_path) as f:
                vulnerability_data = f.read()

            parsed_items = self.parse_advisory_text(vulnerability_data)
            fixed_commits, fixed_versions, affected_commits, affected_versions = [], [], [], []
            advisory_id = file_path.name
            cve_id = None
            summary = None
            description = None
            date_published = None
            for item in parsed_items:
                name = item.get("name")
                if name == "summary":
                    summary = item.get("value")
                elif name == "description":
                    description = item.get("value")
                elif name == "CVE-Id":
                    cve_id = item.get("value")
                elif name == "Public-Date":
                    date_published_value = item.get("value")
                    date_published = dateparser.parse(date_published_value)
                elif name == "Vulnerable-Commit":
                    fix_commit = item.get("commit")
                    affected_commits.append(fix_commit)

                    fixed_version = item.get("version")
                    affected_versions.append(fixed_version)
                elif name == "Fix-Commit":
                    fix_commit = item.get("commit")
                    fixed_commits.append(fix_commit)

                    fixed_version = item.get("version")
                    fixed_versions.append(fixed_version)

            affected_packages = []
            purl = PackageURL(
                type="generic",
                namespace="gnu",
                name="gcc",
            )

            affected_version_range = None
            try:
                affected_version_range = GenericVersionRange.from_versions(affected_versions)
            except InvalidVersion as e:
                logger.error(
                    f"InvalidVersion while parsing affected_version_range: {affected_versions} error: {e}"
                )

            fixed_version_range = None
            try:
                fixed_version_range = GenericVersionRange.from_versions(fixed_versions)
            except InvalidVersion as e:
                logger.error(
                    f"InvalidVersion while parsing fixed_version_range: {fixed_versions} error: {e}"
                )

            fixed_by_commit_patches = [
                PackageCommitPatchData(
                    vcs_url="https://sourceware.org/git/glibc.git", commit_hash=fixed_commit
                )
                for fixed_commit in fixed_commits
            ]
            introduced_by_commit_patches = [
                PackageCommitPatchData(
                    vcs_url="https://sourceware.org/git/glibc.git", commit_hash=affected_commit
                )
                for affected_commit in affected_commits
            ]

            if (
                affected_version_range
                or fixed_version_range
                or introduced_by_commit_patches
                or fixed_by_commit_patches
            ):
                affected_packages.append(
                    AffectedPackageV2(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version_range=fixed_version_range,
                        introduced_by_commit_patches=introduced_by_commit_patches,
                        fixed_by_commit_patches=fixed_by_commit_patches,
                    )
                )

            yield AdvisoryData(
                advisory_id=advisory_id,
                aliases=[cve_id] if cve_id else [],
                summary=build_description(summary, description),
                affected_packages=affected_packages,
                date_published=date_published,
            )

    def parse_advisory_text(self, text):
        summary, _, tail = text.partition("\n\n")
        description, _, metadata = tail.partition("\n\n")

        parsed = [
            {"name": "summary", "value": summary},
            {"name": "description", "value": description},
        ]

        for line in metadata.splitlines():
            name, _, value = line.partition(": ")
            if name.endswith(
                (
                    "Commit",
                    "Backport",
                )
            ):
                commit, _, version = value.partition(" ")
                parsed.append({"name": name, "commit": commit, "version": version.strip(")(")})
            else:
                parsed.append({"name": name, "value": value})
        return parsed

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
