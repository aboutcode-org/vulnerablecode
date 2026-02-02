#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from typing import Iterable

from dateutil.parser import parse
from packageurl import PackageURL
from pytz import UTC
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import AlpineLinuxVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.utils import fetch_response

# See https://docs.tuxcare.com/els-for-os/#cve-status-definition
NON_AFFECTED_STATUSES = ["Not Vulnerable"]
AFFECTED_STATUSES = ["Ignored", "Needs Triage", "In Testing", "In Progress", "In Rollout"]
FIXED_STATUSES = ["Released", "Already Fixed"]

VERSION_RANGE_BY_PURL_TYPE = {
    "rpm": RANGE_CLASS_BY_SCHEMES["rpm"],
    "deb": RANGE_CLASS_BY_SCHEMES["deb"],
    "apk": AlpineLinuxVersionRange,
    "generic": RANGE_CLASS_BY_SCHEMES["generic"],
}


class TuxCareImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "tuxcare_importer_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://tuxcare.com/legal"

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )

    def fetch(self) -> None:
        url = "https://cve.tuxcare.com/els/download-json?orderBy=updated-desc"
        self.log(f"Fetching `{url}`")
        response = fetch_response(url)
        self.response = response.json() if response else []
        self._grouped = self._group_records_by_cve()

    def _group_records_by_cve(self) -> dict:
        """
        A single CVE can appear in multiple records across different operating systems, distributions, or package versions. This method groups all records with the same CVE together and skips entries that are invalid or marked as not affected. The result is a dictionary keyed by CVE ID, with each value containing the related records.
        """
        grouped = {}
        skipped_invalid = 0
        skipped_non_affected = 0

        for record in self.response:
            cve_id = record.get("cve", "").strip()
            if not cve_id:
                self.log(f"Skipping record with empty CVE ID")
                skipped_invalid += 1
                continue

            os_name = record.get("os_name", "").strip()
            project_name = record.get("project_name", "").strip()
            version = record.get("version", "").strip()
            status = record.get("status", "").strip()

            if not all([os_name, project_name, version, status]):
                self.log(f"Skipping {cve_id}: missing required fields")
                skipped_invalid += 1
                continue

            # Skip records with non-affected statuses
            if status in NON_AFFECTED_STATUSES:
                skipped_non_affected += 1
                continue

            if status not in AFFECTED_STATUSES and status not in FIXED_STATUSES:
                self.log(f"Skipping {cve_id}: unrecognized status '{status}'")
                skipped_invalid += 1
                continue

            if cve_id not in grouped:
                grouped[cve_id] = []
            grouped[cve_id].append(record)

        total_skipped = skipped_invalid + skipped_non_affected
        self.log(
            f"Grouped {len(self.response):,d} records into {len(grouped):,d} unique CVEs "
            f"(skipped {total_skipped:,d}: {skipped_invalid:,d} invalid, "
            f"{skipped_non_affected:,d} non-affected)"
        )
        return grouped

    def advisories_count(self) -> int:
        return len(self._grouped)

    def _create_purl(self, project_name: str, os_name: str) -> PackageURL:
        normalized_os = os_name.lower().replace(" ", "-")
        os_lower = os_name.lower()

        os_mapping = {
            "ubuntu": ("deb", "ubuntu"),
            "debian": ("deb", "debian"),
            "centos": ("rpm", "centos"),
            "almalinux": ("rpm", "almalinux"),
            "rhel": ("rpm", "rhel"),
            "oracle": ("rpm", "oracle"),
            "cloudlinux": ("rpm", "cloudlinux"),
            "alpine": ("apk", "alpine"),
            "unknown": ("generic", "tuxcare"),
            "tuxcare": ("generic", "tuxcare"),
        }

        for keyword, (ptype, pns) in os_mapping.items():
            if keyword in os_lower:
                pkg_type = ptype
                namespace = pns
                break
        else:
            return None

        qualifiers = {"distro": normalized_os}

        return PackageURL(
            type=pkg_type, namespace=namespace, name=project_name, qualifiers=qualifiers
        )

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        grouped_by_cve = self._grouped

        for cve_id, records in grouped_by_cve.items():
            affected_packages = []
            severities = []
            date_published = None
            all_records = []

            for record in records:
                os_name = record.get("os_name", "").strip()
                project_name = record.get("project_name", "").strip()
                version = record.get("version", "").strip()
                score = record.get("score", "").strip()
                severity = record.get("severity", "").strip()
                status = record.get("status", "").strip()
                last_updated = record.get("last_updated", "").strip()

                purl = self._create_purl(project_name, os_name)
                if not purl:
                    self.log(
                        f"Skipping package {project_name} on {os_name} for {cve_id} - unexpected OS type"
                    )
                    continue

                version_range_class = VERSION_RANGE_BY_PURL_TYPE.get(purl.type)

                try:
                    version_range = version_range_class.from_versions([version])
                except ValueError as e:
                    self.log(f"Failed to parse version {version} for {cve_id}: {e}")
                    continue

                affected_version_range = None
                fixed_version_range = None

                if status in AFFECTED_STATUSES:
                    affected_version_range = version_range
                elif status in FIXED_STATUSES:
                    fixed_version_range = version_range

                affected_packages.append(
                    AffectedPackageV2(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version_range=fixed_version_range,
                    )
                )

                # Severity is per-CVE hence we add it only once
                if severity and score and not severities:
                    severities.append(
                        VulnerabilitySeverity(
                            system=GENERIC,
                            value=score,
                            scoring_elements=severity,
                        )
                    )

                if last_updated:
                    try:
                        current_date = parse(last_updated).replace(tzinfo=UTC)
                        if date_published is None or current_date > date_published:
                            date_published = current_date
                    except ValueError as e:
                        self.log(f"Failed to parse date {last_updated} for {cve_id}: {e}")

                all_records.append(record)

            if not affected_packages:
                self.log(f"Skipping {cve_id} - no valid affected packages")
                continue

            yield AdvisoryData(
                advisory_id=cve_id,
                affected_packages=affected_packages,
                severities=severities,
                date_published=date_published,
                url=f"https://cve.tuxcare.com/els/cve/{cve_id}",
                original_advisory_text=json.dumps(all_records, indent=2, ensure_ascii=False),
            )
