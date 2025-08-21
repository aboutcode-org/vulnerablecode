#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from typing import Iterable

import requests
import yaml
from packageurl import PackageURL
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.elixir_security_importer import (
    ElixirSecurityImporterPipeline,
)


class ElixirSecurityLiveImporterPipeline(ElixirSecurityImporterPipeline):
    """
    Elixir Security Advisories Importer Pipeline

    This pipeline imports security advisories for a single elixir PURL.
    """

    pipeline_id = "elixir_security_live_importer_v2"
    supported_types = ["hex"]

    @classmethod
    def steps(cls):
        return (
            cls.get_purl_inputs,
            cls.collect_and_store_advisories,
        )

    def get_purl_inputs(self):
        purl = self.inputs["purl"]
        if not purl:
            raise ValueError("PURL is required for ElixirSecurityLiveImporterPipeline")

        if isinstance(purl, str):
            purl = PackageURL.from_string(purl)

        if not isinstance(purl, PackageURL):
            raise ValueError(f"Object of type {type(purl)} {purl!r} is not a PackageURL instance")

        if purl.type not in self.supported_types:
            raise ValueError(
                f"PURL: {purl!s} is not among the supported package types {self.supported_types!r}"
            )

        if not purl.version:
            raise ValueError(f"PURL: {purl!s} is expected to have a version")

        self.purl = purl

    def advisories_count(self) -> int:
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

            yaml_entries = [file for file in response.json() if file["name"].endswith(".yml")]

            for entry in yaml_entries:
                # entry["path"] looks like: packages/<pkg>/<file>.yml
                file_path = entry["path"]
                content_url = f"https://api.github.com/repos/dependabot/elixir-security-advisories/contents/{file_path}"
                content_response = requests.get(
                    content_url, headers={"Accept": "application/vnd.github.v3.raw"}
                )

                if content_response.status_code != 200:
                    self.log(f"Failed to fetch file content for {file_path}")
                    continue

                advisory_text = content_response.text

                try:
                    yaml_file = yaml.safe_load(advisory_text) or {}
                except Exception as e:
                    self.log(f"Failed to parse YAML for {file_path}: {e}")
                    continue

                for advisory in self.build_advisory_from_yaml(
                    yaml_file=yaml_file, advisory_text=advisory_text, relative_path=file_path
                ):
                    if self.purl.version and not self._advisory_affects_version(advisory):
                        continue
                    yield advisory

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
