#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import re
from pathlib import Path
from typing import Iterable
from typing import List

from packageurl import PackageURL
from univers.version_range import NugetVersionRange
from univers.versions import NugetVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference


class RetireDotnetImporter(Importer):
    license_url = "https://github.com/RetireNet/Packages/blob/master/LICENSE"
    spdx_license_expression = "MIT"
    repo_url = "git+https://github.com/RetireNet/Packages/"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone(self.repo_url)
            path = Path(self.vcs_response.dest_dir)

            vuln = path / "Content"
            for file in vuln.glob("*.json"):
                advisory = self.process_file(file)
                if advisory:
                    yield advisory
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    @staticmethod
    def vuln_id_from_desc(desc):
        cve_regex = re.compile(r"CVE-\d+-\d+")
        res = cve_regex.search(desc)
        if res:
            return desc[res.start() : res.end()]
        else:
            return None

    def process_file(self, path) -> List[AdvisoryData]:
        with open(path) as f:
            json_doc = json.load(f)
            description = json_doc.get("description") or ""
            alias = self.vuln_id_from_desc(description)
            affected_packages = []
            for pkg in json_doc.get("packages") or []:
                name = pkg.get("id")
                if not name:
                    continue
                affected_version_range = None
                fixed_version = None
                if pkg.get("affected"):
                    affected_version_range = NugetVersionRange.from_versions([pkg["affected"]])
                if pkg.get("fix"):
                    fixed_version = NugetVersion(pkg["fix"])
                if not affected_version_range and not fixed_version:
                    continue
                affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(name=name, type="nuget"),
                        affected_version_range=affected_version_range,
                        fixed_version=fixed_version,
                    )
                )

            link = json_doc.get("link")
            if link:
                vuln_reference = [
                    Reference(
                        url=link,
                    )
                ]
            if alias:
                return AdvisoryData(
                    aliases=[alias],
                    summary=description,
                    affected_packages=affected_packages,
                    references=vuln_reference,
                )
