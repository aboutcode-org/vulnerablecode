#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from typing import Iterable

from dateutil import parser as dateparser
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import HexVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import is_cve
from vulnerabilities.utils import load_yaml


class ElixirSecurityImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Elixir Security Advisiories Importer Pipeline

    This pipeline imports security advisories for elixir.
    """

    pipeline_id = "elixir_security_importer_v2"
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/dependabot/elixir-security-advisories/blob/master/LICENSE.txt"
    repo_url = "git+https://github.com/dependabot/elixir-security-advisories"
    unfurl_version_ranges = True

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self) -> int:
        base_path = Path(self.vcs_response.dest_dir)
        count = len(list((base_path / "packages").glob("**/*.yml")))
        return count

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        try:
            base_path = Path(self.vcs_response.dest_dir)
            vuln = base_path / "packages"
            for file in vuln.glob("**/*.yml"):
                yield from self.process_file(file, base_path)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def process_file(self, file, base_path) -> Iterable[AdvisoryData]:
        relative_path = str(file.relative_to(base_path)).strip("/")
        advisory_url = (
            f"https://github.com/dependabot/elixir-security-advisories/blob/master/{relative_path}"
        )
        yaml_file = load_yaml(str(file))

        summary = yaml_file.get("description") or ""
        pkg_name = yaml_file.get("package") or ""

        cve_id = ""
        cve = yaml_file.get("cve") or ""
        if cve and not cve.startswith("CVE-"):
            cve_id = f"CVE-{cve}"
        elif cve:
            cve_id = cve

        if not cve_id or not is_cve(cve_id):
            return

        references = []
        link = yaml_file.get("link") or ""
        if link:
            references.append(ReferenceV2(url=link))

        constraints = []
        vrc = HexVersionRange.version_class
        unaffected_versions = yaml_file.get("unaffected_versions") or []
        patched_versions = yaml_file.get("patched_versions") or []

        for version in unaffected_versions:
            constraints.append(VersionConstraint.from_string(version_class=vrc, string=version))

        for version in patched_versions:
            if version.startswith("~>"):
                version = version[2:]
            constraints.append(
                VersionConstraint.from_string(version_class=vrc, string=version).invert()
            )

        affected_packages = []
        if pkg_name:
            affected_packages.append(
                AffectedPackage(
                    package=PackageURL(type="hex", name=pkg_name),
                    affected_version_range=HexVersionRange(constraints=constraints),
                )
            )

        date_published = None
        if yaml_file.get("disclosure_date"):
            date_published = dateparser.parse(yaml_file.get("disclosure_date"))

        yield AdvisoryData(
            advisory_id=cve_id,
            aliases=[],
            summary=summary,
            references_v2=references,
            affected_packages=affected_packages,
            url=advisory_url,
            date_published=date_published,
        )
