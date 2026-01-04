import json
import logging
from typing import Iterable

from dateutil import parser as date_parser
from django.utils import timezone
from packageurl import PackageURL
from univers.version_range import GenericVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.utils import fetch_response

logger = logging.getLogger(__name__)


class TuxCareImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "tuxcare_importer_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://tuxcare.com/legal"
    url = "https://cve.tuxcare.com/els/download-json?orderBy=updated-desc"

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def advisories_count(self) -> int:
        response = fetch_response(self.url)
        data = response.json() if response else []
        return len(data)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        response = fetch_response(self.url)
        if not response:
            return

        data = response.json()
        if not data:
            return

        for record in data:
            cve_id = record.get("cve", "").strip()
            if not cve_id or not cve_id.startswith("CVE-"):
                continue

            os_name = record.get("os_name", "").strip()
            project_name = record.get("project_name", "").strip()
            version = record.get("version", "").strip()
            score = record.get("score", "").strip()
            severity = record.get("severity", "").strip()
            status = record.get("status", "").strip()
            last_updated = record.get("last_updated", "").strip()

            safe_os = os_name.replace(" ", "_") if os_name else "unknown"
            advisory_id = f"TUXCARE-{cve_id}-{safe_os}-{project_name}"

            summary = f"TuxCare advisory for {cve_id}"
            if project_name:
                summary += f" in {project_name}"
            if os_name:
                summary += f" on {os_name}"

            affected_packages = []
            if project_name:
                purl = PackageURL(type="generic", name=project_name)
                
                affected_version_range = None
                if version:
                    try:
                        affected_version_range = GenericVersionRange.from_versions([version])
                    except Exception:
                        pass

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
                        value=f"{severity} ({score})",
                        scoring_elements=f"score={score},severity={severity}",
                    )
                )

            date_published = None
            if last_updated:
                try:
                    date_published = date_parser.parse(last_updated)
                    if timezone.is_naive(date_published):
                        date_published = timezone.make_aware(date_published, timezone=timezone.utc)
                except Exception:
                    pass

            yield AdvisoryData(
                advisory_id=advisory_id,
                aliases=[cve_id],
                summary=summary,
                affected_packages=affected_packages,
                references_v2=[ReferenceV2(url="https://cve.tuxcare.com/")],
                severities=severities,
                date_published=date_published,
                url="https://cve.tuxcare.com/",
                original_advisory_text=json.dumps(record, indent=2, ensure_ascii=False),
            )
