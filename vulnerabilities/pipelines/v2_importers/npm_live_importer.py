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

from packageurl import PackageURL
from univers.versions import InvalidVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.npm_importer import NpmImporterPipeline
from vulnerabilities.utils import load_json


class NpmLiveImporterPipeline(NpmImporterPipeline):
    """
    Node.js Security Working Group importer pipeline

    Import advisories from nodejs security working group including node proper advisories and npm advisories for a single PURL.
    """

    pipeline_id = "nodejs_security_wg_live_importer"
    supported_types = ["npm"]

    @classmethod
    def steps(cls):
        return (
            cls.get_purl_inputs,
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def get_purl_inputs(self):
        purl = self.inputs["purl"]
        if not purl:
            raise ValueError("PURL is required for NpmLiveImporterPipeline")

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

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        vuln_directory = Path(self.vcs_response.dest_dir) / "vuln" / "npm"
        package_name = self.purl.name
        filtered_files = []
        for advisory_file in vuln_directory.glob("*.json"):
            data = load_json(advisory_file)
            if data.get("module_name") == package_name:
                affected_package = self.get_affected_package(data, package_name)
                if not self.purl.version or self._version_is_related(affected_package):
                    filtered_files.append(advisory_file)

        for advisory in filtered_files:
            result = self.to_advisory_data(advisory)
            if result:
                yield result

    def _version_is_related(self, affected_package):
        try:
            package_version = SemverVersion(self.purl.version)
        except InvalidVersion as e:
            self.log(f"Invalid PURL version: {self.purl.version!r}: {str(e)}")
            return False

        if (
            affected_package.affected_version_range
            and package_version in affected_package.affected_version_range
        ) or (
            affected_package.fixed_version_range
            and package_version in affected_package.fixed_version_range
        ):
            return True
        return False
