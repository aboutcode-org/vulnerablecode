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
import saneyaml
from packageurl import PackageURL
from univers.versions import PypiVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2


class PyPaLiveImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pypa Live Importer Pipeline

    Collect advisories from PyPA GitHub repository for a single PURL.
    """

    pipeline_id = "pypa_live_importer_v2"
    supported_types = ["pypi"]
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/pypa/advisory-database/blob/main/LICENSE"

    @classmethod
    def steps(cls):
        return (
            cls.get_purl_inputs,
            cls.fetch_package_advisories,
            cls.collect_and_store_advisories,
        )

    def get_purl_inputs(self):
        purl = self.inputs["purl"]
        if not purl:
            raise ValueError("PURL is required for PyPaLiveImporterPipeline")

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

    def _is_version_affected(self, advisory_dict, version):
        affected = advisory_dict.get("affected", [])
        try:
            v = PypiVersion(version)
        except Exception:
            return False
        for entry in affected:
            ranges = entry.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                introduced = None
                fixed = None
                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                try:
                    if introduced:
                        introduced_v = PypiVersion(introduced)
                        if v < introduced_v:
                            continue
                    if fixed:
                        fixed_v = PypiVersion(fixed)
                        if v >= fixed_v:
                            continue
                    if introduced:
                        introduced_v = PypiVersion(introduced)
                        if (not fixed or v < PypiVersion(fixed)) and v >= introduced_v:
                            return True
                except Exception:
                    continue
        return False

    def fetch_package_advisories(self):
        if not self.purl.type in self.supported_types:
            return

        search_path = f"vulns/{self.purl.name}"

        self.package_advisories = []

        api_url = f"https://api.github.com/repos/pypa/advisory-database/contents/{search_path}"
        response = requests.get(api_url)

        if response.status_code == 404:
            self.log(f"No advisories found for package {self.purl.name}")
            return

        if response.status_code != 200:
            self.log(f"Failed to fetch advisories: {response.status_code} {response.text}")
            return

        for item in response.json():
            if item["type"] == "file" and item["name"].endswith(".yaml"):
                file_url = item["download_url"]
                self.log("Fetching advisory file: " + item["name"])
                file_response = requests.get(file_url)

                if file_response.status_code == 200:
                    advisory_text = file_response.text
                    advisory_dict = saneyaml.load(advisory_text)

                    if self.purl.version and not self._is_version_affected(
                        advisory_dict, self.purl.version
                    ):
                        continue

                    self.package_advisories.append(
                        {"text": advisory_text, "dict": advisory_dict, "url": item["html_url"]}
                    )

    def advisories_count(self):
        return len(self.package_advisories) if hasattr(self, "package_advisories") else 0

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        from vulnerabilities.importers.osv import parse_advisory_data_v2

        if not hasattr(self, "package_advisories"):
            return

        for advisory in self.package_advisories:
            yield parse_advisory_data_v2(
                raw_data=advisory["dict"],
                supported_ecosystems=self.supported_types,
                advisory_url=advisory["url"],
                advisory_text=advisory["text"],
            )
