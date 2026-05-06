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
from packageurl import PackageURL
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.elixir_security_importer import (
    ElixirSecurityImporterPipeline,
)
from vulnerabilities.utils import fetch_yaml


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

        self.purl = purl

    def advisories_count(self) -> int:
        return 0

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
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
                advisory_url = f"https://api.github.com/repos/dependabot/elixir-security-advisories/contents/{file_path}"
                advisory_text = fetch_yaml(
                    advisory_url, headers={"Accept": "application/vnd.github.v3.raw"}
                )

                path_segments = str(file_path).split("/")
                # use the last two segments as the advisory ID
                advisory_id = "/".join(path_segments[-2:]).replace(".yml", "")

                for advisory in self.build_advisory_from_text(
                    advisory_id=advisory_id,
                    yaml_file=advisory_text,
                    advisory_url=advisory_url,
                ):
                    if self.purl.version and not self.validate_advisory(advisory):
                        continue
                    yield advisory

        except Exception as e:
            self.log(f"Error fetching advisories for {self.purl}: {str(e)}")
            return []

    def validate_advisory(self, advisory: AdvisoryDataV2) -> bool:
        if not self.purl.version:
            return True

        for affected_package in advisory.affected_packages:
            try:
                purl_version = SemverVersion(self.purl.version)
                if (
                    affected_package.affected_version_range
                    and purl_version in affected_package.affected_version_range
                ) or (
                    affected_package.fixed_version_range
                    and purl_version in affected_package.fixed_version_range
                ):
                    return True

            except Exception as e:
                self.log(f"Failed to parse version {self.purl.version}: {str(e)}")
                #  Since we have a small package file, if we fail to parse the versions, we can just return all of them
                return True
        return False
