#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import re
from collections import defaultdict
from pathlib import Path

from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import NugetVersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import get_advisory_url


class RetireDotnetImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    license_url = "https://github.com/RetireNet/Packages/blob/master/LICENSE"
    spdx_license_expression = "MIT"
    repo_url = "git+https://github.com/RetireNet/Packages/"
    pipeline_id = "retiredotnet_importer_v2"
    run_once = True

    precedence = 200

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
        root = Path(self.vcs_response.dest_dir) / "Content"
        return sum(1 for _ in root.rglob("*.json"))

    def collect_advisories(self):
        base_path = Path(self.vcs_response.dest_dir)
        vuln = base_path / "Content"
        affected_packages = []

        for file in vuln.glob("*.json"):
            advisory_id = "retiredotnet-" + file.stem
            advisory_url = get_advisory_url(
                file=file,
                base_path=base_path,
                url="https://github.com/RetireNet/Packages/blob/master/",
            )
            with open(file) as f:
                json_doc = json.load(f)
                description = json_doc.get("description") or ""
                aliases = self.vuln_id_from_desc(description)

                # group by package name `id`
                # { pkg_id: {'affected_versions': set(), 'fixed': set()} }
                grouped_packages = defaultdict(
                    lambda: {"affected_versions": set(), "fixed_versions": set()}
                )
                for pkg in json_doc.get("packages") or []:
                    name = pkg.get("id")
                    if not name:
                        continue

                    affected_version = pkg.get("affected")
                    if affected_version:
                        grouped_packages[name]["affected_versions"].add(affected_version)

                    fixed_version = pkg.get("fix")
                    if fixed_version:
                        grouped_packages[name]["fixed_versions"].add(fixed_version)

                for pkg in grouped_packages:
                    affected_version_range = None
                    affected_versions = grouped_packages[pkg]["affected_versions"]
                    if affected_versions:
                        affected_version_range = NugetVersionRange.from_versions(affected_versions)

                    fixed_version_range = None
                    fixed_versions = grouped_packages[pkg]["fixed_versions"]
                    if fixed_versions:
                        fixed_version_range = NugetVersionRange.from_versions(fixed_versions)

                    if affected_version_range or fixed_version_range:
                        affected_packages.append(
                            AffectedPackageV2(
                                package=PackageURL(type="nuget", name=pkg),
                                affected_version_range=affected_version_range,
                                fixed_version_range=fixed_version_range,
                            )
                        )

                link = json_doc.get("link")
                if link:
                    vuln_reference = [
                        ReferenceV2(
                            url=link,
                        )
                    ]

                yield AdvisoryDataV2(
                    advisory_id=advisory_id,
                    aliases=[aliases] if aliases else [],
                    summary=description,
                    affected_packages=affected_packages,
                    references=vuln_reference,
                    url=advisory_url,
                )

    @staticmethod
    def vuln_id_from_desc(desc):
        cve_regex = re.compile(r"CVE-\d+-\d+")
        res = cve_regex.search(desc)
        if res:
            return desc[res.start() : res.end()]
        else:
            return None

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
