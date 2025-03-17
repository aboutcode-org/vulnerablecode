#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import urllib.parse as urlparse
from pathlib import Path
from typing import Set

from dateutil import parser as dateparser
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
    importer_name = "Elixir Security Importer"

    def advisory_data(self) -> Set[AdvisoryData]:
        try:
            self.clone(self.repo_url)
            base_path = Path(self.vcs_response.dest_dir)
            vuln = base_path / "packages"
            for file in vuln.glob("**/*.yml"):
                yield from self.process_file(file, base_path)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def process_file(self, file, base_path):
        relative_path = str(file.relative_to(base_path)).strip("/")
        advisory_url = (
            f"https://github.com/dependabot/elixir-security-advisories/blob/master/{relative_path}"
        )
        file = str(file)
        yaml_file = load_yaml(file)
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

        date_published = None
        if yaml_file.get("disclosure_date"):
            date_published = dateparser.parse(yaml_file.get("disclosure_date"))

        yield AdvisoryData(
            aliases=[cve_id],
            summary=summary,
            references=references,
            affected_packages=affected_packages,
            url=advisory_url,
            date_published=date_published,
        )
