#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
import os
import tempfile
from pathlib import Path
from typing import Set

import requests
from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import HexVersionRange
from univers.versions import SemverVersion

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

    def __init__(self, purl=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.purl = purl
        if self.purl:
            if self.purl.type != "hex":
                print(
                    f"Warning: PURL type {self.purl.type} is not 'hex', may not match any advisories"
                )

    def advisory_data(self) -> Set[AdvisoryData]:
        if not self.purl:
            return self._batch_advisory_data()

        return self._package_first_advisory_data()

    def _batch_advisory_data(self) -> Set[AdvisoryData]:
        try:
            self.clone(self.repo_url)
            base_path = Path(self.vcs_response.dest_dir)
            vuln = base_path / "packages"
            for file in vuln.glob("**/*.yml"):
                yield from self.process_file(file, base_path)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def _package_first_advisory_data(self) -> Set[AdvisoryData]:
        if self.purl.type != "hex":
            logging.warning(
                f"PURL type {self.purl.type} is not supported by Elixir Security importer"
            )
            return []

        package_name = self.purl.name

        try:
            directory_url = f"https://api.github.com/repos/dependabot/elixir-security-advisories/contents/packages/{package_name}"
            response = requests.get(directory_url)

            if response.status_code != 200:
                logging.info(f"No advisories found for {package_name} in Elixir Security Database")
                return []

            yaml_files = [file["path"] for file in response.json() if file["name"].endswith(".yml")]

            for file_path in yaml_files:
                content_url = f"https://api.github.com/repos/dependabot/elixir-security-advisories/contents/{file_path}"
                content_response = requests.get(
                    content_url, headers={"Accept": "application/vnd.github.v3.raw"}
                )

                if content_response.status_code != 200:
                    logging.warning(f"Failed to fetch file content for {file_path}")
                    continue

                # Create a temporary file to store the content
                with tempfile.NamedTemporaryFile(mode="w+", delete=False) as temp_file:
                    temp_file.write(content_response.text)
                    temp_path = temp_file.name

                try:
                    for advisory in self.process_file(temp_path, Path(""), file_path=file_path):
                        if self.purl.version and not self._advisory_affects_version(advisory):
                            continue

                        yield advisory
                finally:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)

        except Exception as e:
            logging.error(f"Error fetching advisories for {self.purl}: {str(e)}")
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
                    logging.warning(f"Failed to parse version {self.purl.version}: {str(e)}")
                    return True

        return False

    def process_file(self, file, base_path, file_path=None):
        if file_path:
            relative_path = file_path
        else:
            relative_path = str(Path(file).relative_to(base_path)).strip("/")

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
