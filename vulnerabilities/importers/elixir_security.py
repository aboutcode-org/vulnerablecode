#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from pathlib import Path
from typing import Set

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import HexVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.utils import is_cve
from vulnerabilities.utils import load_yaml


class ElixirSecurityImporter(Importer):
    repo_url = "git+https://github.com/dependabot/elixir-security-advisories"
    license_url = "https://github.com/dependabot/elixir-security-advisories/blob/master/LICENSE.txt"
    spdx_license_expression = "CC0-1.0"

    def advisory_data(self) -> Set[AdvisoryData]:
        try:
            self.clone(self.repo_url)
            path = Path(self.vcs_response.dest_dir)
            vuln = path / "packages"
            for file in vuln.glob("**/*.yml"):
                yield from self.process_file(file)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def process_file(self, path):
        path = str(path)
        yaml_file = load_yaml(path)
        cve_id = ""
        summary = yaml_file.get("description") or ""
        pkg_name = yaml_file.get("package") or ""

        cve = yaml_file.get("cve") or ""

        if cve and not cve.startswith("CVE-"):
            cve_id = f"CVE-{cve}"

        if not cve_id:
            return []

        if not is_cve(cve_id):
            return []

        references = []
        link = yaml_file.get("link") or ""
        if link:
            references.append(
                Reference(
                    url=link,
                )
            )

        affected_packages = []

        unaffected_versions = yaml_file.get("unaffected_versions") or []
        patched_versions = yaml_file.get("patched_versions") or []

        constraints = []
        vrc = HexVersionRange.version_class

        for version in unaffected_versions:
            constraints.append(VersionConstraint.from_string(version_class=vrc, string=version))

        for version in patched_versions:
            if version.startswith("~>"):
                version = version[2:]
            constraints.append(
                VersionConstraint.from_string(version_class=vrc, string=version).invert()
            )

        if pkg_name:
            affected_packages.append(
                AffectedPackage(
                    package=PackageURL(
                        type="hex",
                        name=pkg_name,
                    ),
                    affected_version_range=HexVersionRange(constraints=constraints),
                )
            )

        yield AdvisoryData(
            aliases=[cve_id],
            summary=summary,
            references=references,
            affected_packages=affected_packages,
        )
