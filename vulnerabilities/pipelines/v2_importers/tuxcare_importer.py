import json
import logging
from typing import Iterable, Mapping

from dateutil.parser import parse
from packageurl import PackageURL
from pytz import UTC
from univers.version_range import GenericVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.utils import fetch_response

logger = logging.getLogger(__name__)


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

    def fetch(self) -> Iterable[Mapping]:
        url = "https://cve.tuxcare.com/els/download-json?orderBy=updated-desc"
        self.log(f"Fetching `{url}`")
        response = fetch_response(url)
        self.response = response.json() if response else []

    def advisories_count(self) -> int:
        return len(self.response)

    def _create_purl(self, project_name: str, os_name: str) -> PackageURL:
        os_mapping = {
            "ubuntu": ("deb", "ubuntu"),
            "debian": ("deb", "debian"),
            "centos": ("rpm", "centos"),
            "almalinux": ("rpm", "almalinux"),
            "rhel": ("rpm", "redhat"),
            "red hat": ("rpm", "redhat"),
            "oracle": ("rpm", "oracle"),
            "cloudlinux": ("rpm", "cloudlinux"),
            "alpine": ("apk", "alpine"),
        }

        qualifiers = {}
        if os_name:
            qualifiers["os"] = os_name

        if not os_name:
            return PackageURL(type="generic", name=project_name)

        os_lower = os_name.lower()
        for keyword, (pkg_type, namespace) in os_mapping.items():
            if keyword in os_lower:
                return PackageURL(
                    type=pkg_type, namespace=namespace, name=project_name, qualifiers=qualifiers
                )

        return PackageURL(type="generic", name=project_name, qualifiers=qualifiers)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        for record in self.response:
            cve_id = record.get("cve", "").strip()
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            os_name = record.get("os_name", "").strip()
            project_name = record.get("project_name", "").strip()
            version = record.get("version", "").strip()
            score = record.get("score", "").strip()
            severity = record.get("severity", "").strip()
            last_updated = record.get("last_updated", "").strip()

            advisory_id = cve_id

            summary = f"TuxCare advisory for {cve_id}"
            if project_name:
                summary += f" in {project_name}"
            if os_name:
                summary += f" on {os_name}"

            affected_packages = []
            if project_name:
                purl = self._create_purl(project_name, os_name)

                affected_version_range = None
                if version:
                    try:
                        affected_version_range = GenericVersionRange.from_versions([version])
                    except ValueError as e:
                        logger.warning(f"Failed to parse version {version} for {cve_id}: {e}")

                affected_packages.append(
                    AffectedPackageV2(
                        package=purl,
                        affected_version_range=affected_version_range,
                    )
                )

            severities = []
            if severity and score:
                severities.append(
                    VulnerabilitySeverity(
                        system=GENERIC,
                        value=score,
                        scoring_elements=severity,
                    )
                )

            date_published = None
            if last_updated:
                try:
                    date_published = parse(last_updated).replace(tzinfo=UTC)
                except ValueError as e:
                    logger.warning(f"Failed to parse date {last_updated} for {cve_id}: {e}")

            yield AdvisoryData(
                advisory_id=advisory_id,
                summary=summary,
                affected_packages=affected_packages,
                severities=severities,
                date_published=date_published,
                url=f"https://cve.tuxcare.com/els/cve/{cve_id}",
                original_advisory_text=json.dumps(record, indent=2, ensure_ascii=False),
            )
