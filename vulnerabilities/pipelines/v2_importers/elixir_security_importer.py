#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import tempfile
from pathlib import Path
from typing import Iterable

import requests
from dateutil import parser as dateparser
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import HexVersionRange
from univers.versions import SemverVersion

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

    is_batch_run = True

    def __init__(self, *args, purl=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.purl = purl
        if self.purl:
            ElixirSecurityImporterPipeline.is_batch_run = False
            if self.purl.type != "hex":
                self.log(
                    f"Warning: PURL type {self.purl.type} is not 'hex', may not match any advisories"
                )

    @classmethod
    def steps(cls):
        if not cls.is_batch_run:
            return (cls.collect_and_store_advisories,)
        return (cls.clone, cls.collect_and_store_advisories, cls.clean_downloads)

    def clean_downloads(self):
        if self.is_batch_run and self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def clone(self):
        if self.is_batch_run:
            self.log(f"Cloning `{self.repo_url}`")
            self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self) -> int:
        if not self.is_batch_run:
            return self._count_package_advisories()

        base_path = Path(self.vcs_response.dest_dir)
        count = len(list((base_path / "packages").glob("**/*.yml")))
        return count

    def _count_package_advisories(self) -> int:
        if self.purl.type != "hex":
            return 0

        try:
            directory_url = f"https://api.github.com/repos/dependabot/elixir-security-advisories/contents/packages/{self.purl.name}"
            response = requests.get(directory_url)

            if response.status_code != 200:
                return 0

            yaml_files = [file for file in response.json() if file["name"].endswith(".yml")]
            return len(yaml_files)
        except Exception:
            return 0

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        if not self.is_batch_run:
            return self._collect_package_advisories()

        return self._collect_batch_advisories()

    def _collect_batch_advisories(self) -> Iterable[AdvisoryData]:
        try:
            base_path = Path(self.vcs_response.dest_dir)
            vuln = base_path / "packages"
            for file in vuln.glob("**/*.yml"):
                yield from self.process_file(file, base_path)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def _collect_package_advisories(self) -> Iterable[AdvisoryData]:
        if self.purl.type != "hex":
            self.log(f"PURL type {self.purl.type} is not supported by Elixir Security importer")
            return []

        package_name = self.purl.name

        try:
            directory_url = f"https://api.github.com/repos/dependabot/elixir-security-advisories/contents/packages/{package_name}"
            response = requests.get(directory_url)

            if response.status_code != 200:
                self.log(f"No advisories found for {package_name} in Elixir Security Database")
                return []

            yaml_files = [file["path"] for file in response.json() if file["name"].endswith(".yml")]

            for file_path in yaml_files:
                content_url = f"https://api.github.com/repos/dependabot/elixir-security-advisories/contents/{file_path}"
                content_response = requests.get(
                    content_url, headers={"Accept": "application/vnd.github.v3.raw"}
                )

                if content_response.status_code != 200:
                    self.log(f"Failed to fetch file content for {file_path}")
                    continue

                # Create a temporary file to store the content
                with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
                    temp_file.write(content_response.text)
                    temp_path = temp_file.name

                try:
                    for advisory in self.process_file(
                        Path(temp_path), Path(""), file_path=file_path
                    ):
                        if self.purl.version and not self._advisory_affects_version(advisory):
                            continue

                        yield advisory
                finally:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)

        except Exception as e:
            self.log(f"Error fetching advisories for {self.purl}: {str(e)}")
            return []

    def _advisory_affects_version(self, advisory: AdvisoryData) -> bool:
        if not self.purl.version:
            return True

        for affected_package in advisory.affected_packages:
            if affected_package.affected_version_range:
                try:
                    purl_version = SemverVersion(self.purl.version)

                    if purl_version in affected_package.affected_version_range:
                        return True
                except Exception as e:
                    self.log(f"Failed to parse version {self.purl.version}: {str(e)}")
                    return True

        return False

    def process_file(self, file, base_path, file_path=None) -> Iterable[AdvisoryData]:
        if file_path:
            relative_path = file_path
            advisory_id = (
                file_path.replace(".yml", "").split("/")[-2]
                + "/"
                + file_path.replace(".yml", "").split("/")[-1]
            )
        else:
            relative_path = str(file.relative_to(base_path)).strip("/")
            path_segments = str(file).split("/")
            advisory_id = "/".join(path_segments[-2:]).replace(".yml", "")

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
            advisory_id=advisory_id,
            aliases=[cve_id],
            summary=summary,
            references_v2=references,
            affected_packages=affected_packages,
            url=advisory_url,
            date_published=date_published,
        )
