#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import re
from typing import Iterable

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import RpmVersionRange
from univers.versions import RpmVersion

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.utils import fetch_response


class VmwarePhotonImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect advisories from Vmware Photon Advisory.

    Example of advisory
    {
    "cve_id": "CVE-2020-11979",
    "pkg": "apache-ant",
    "cve_score": 7.5,
    "aff_ver": "all versions before 1.10.8-2.ph1 are vulnerable",
    "res_ver": "1.10.8-2.ph1"
    }
    """

    pipeline_id = "vmware_photon_importer_v2"
    spdx_license_expression = "CC BY-SA 4.0"
    license_url = "https://creativecommons.org/licenses/by-sa/4.0"
    repo_url = "https://packages.vmware.com/photon/photon_cve_metadata/"

    precedence = 100

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.group_records_by_cve,
            cls.collect_and_store_advisories,
        )

    def fetch(self):
        """
        Fetches all JSON files from the repository index and extracts records. Each record is enriched with the source URL(contains the  photon version) for traceability.
        """
        self.records = []
        response = fetch_response(self.repo_url)
        photon_files = re.findall(r'href="(cve_data_photon[0-9.]+\.json)"', response.text)

        for file_name in photon_files:
            source_url = self.repo_url + file_name
            self.log(f"Fetching `{source_url}`")
            response = fetch_response(source_url)
            for record in response.json():
                record["source_url"] = source_url
                self.records.append(record)
        self.log(f"Fetched {len(self.records):,d} total records from {len(photon_files)} sources")

    def group_records_by_cve(self):
        """
        A particular CVE may have more than one record. This method groups records by CVE ID and filters "Not Affected" records.
        """
        self.cve_to_records = {}
        skipped_non_affected = 0

        for record in self.records:
            cve_id = record.get("cve_id")

            # Skip records that are marked as "Not Affected"
            if record.get("status") == "Not Affected":
                skipped_non_affected += 1
                continue

            self.cve_to_records.setdefault(cve_id, []).append(record)

        self.log(
            f"Grouped {len(self.records):,d} records into {len(self.cve_to_records):,d} unique CVEs "
            f"(skipped {skipped_non_affected:,d} non-affected)"
        )

    def advisories_count(self) -> int:
        return len(self.cve_to_records)

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for cve_id, records in self.cve_to_records.items():
            affected_packages = []

            for record in records:
                pkg_name = record.get("pkg")
                aff_ver = record.get("aff_ver")
                res_ver = record.get("res_ver")

                # Example PURL Format: pkg:rpm/vmware/apache-ant?distro=photon
                purl = PackageURL(
                    type="rpm",
                    namespace="vmware",
                    name=pkg_name,
                    qualifiers={"distro": "photon"},
                )

                ver_match = re.match(r"all versions before (.+) are vulnerable", aff_ver)

                if not ver_match:
                    self.log(f"Could not extract affected version from aff_ver: {aff_ver!r}")
                    continue

                aff_ver = ver_match.group(1)
                affected_version_range = RpmVersionRange(
                    constraints=[
                        VersionConstraint(
                            comparator="<",
                            version=RpmVersion(aff_ver),
                        )
                    ]
                )

                fixed_version_range = RpmVersionRange.from_versions([res_ver])

                affected_packages.append(
                    AffectedPackageV2(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version_range=fixed_version_range,
                    )
                )

            severities = []
            cve_score = records[0].get("cve_score")
            severities.append(
                VulnerabilitySeverity(
                    system=GENERIC,
                    value=str(cve_score),
                )
            )

            yield AdvisoryDataV2(
                advisory_id=cve_id,
                affected_packages=affected_packages,
                severities=severities,
                url=records[0].get("source_url", self.repo_url),
                original_advisory_text=json.dumps(records, indent=2, ensure_ascii=False),
            )
