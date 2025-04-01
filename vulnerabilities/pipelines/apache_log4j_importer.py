#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
from collections import defaultdict
from typing import Iterable

import pytz
from cyclonedx.model.bom import Bom
from dateutil.parser import parse
from defusedxml import ElementTree as SafeElementTree
from packageurl import PackageURL
from univers.versions import MavenVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import get_cwe_id

logger = logging.getLogger(__name__)


class ApacheLog4jImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """
    Import security advisories from Apache Log4j's security database.
    """

    pipeline_id = "apache_log4j_importer"
    XML_URL = "https://logging.apache.org/cyclonedx/vdr.xml"
    ASF_PAGE_URL = "https://logging.apache.org/security.html"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/"
    importer_name = "Apache Log4j Importer"

    version_set = [
        "2.0-beta1",
        "2.0-beta2",
        "2.0-beta3",
        "2.0-beta5",
        "2.0-alpha1",
        "2.0-beta7",
        "2.0-beta8",
        "2.0-beta9",
        "2.0-rc1",
        "2.0-beta4",
        "2.0-beta6",
        "2.0-rc2",
        "2.0",
        "2.0.1",
        "2.0.2",
        "2.1",
        "2.2",
        "2.3",
        "2.3.1",
        "2.3.2",
        "2.4",
        "2.4.1",
        "2.5",
        "2.6",
        "2.6.1",
        "2.6.2",
        "2.7",
        "2.8",
        "2.8.1",
        "2.8.2",
        "2.9.0",
        "2.9.1",
        "2.10.0",
        "2.11.0",
        "2.11.1",
        "2.11.2",
        "2.12.0",
        "2.12.1",
        "2.12.2",
        "2.12.3",
        "2.12.4",
        "2.13.0",
        "2.13.1",
        "2.13.2",
        "2.13.3",
        "2.14.0",
        "2.14.1",
        "2.15.0",
        "2.15.1",
        "2.16.0",
        "2.17.0",
        "2.17.1",
    ]

    @classmethod
    def steps(cls):
        """
        Return pipeline steps.
        """
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    def advisories_count(self) -> int:
        """
        Return total number of advisories.
        """
        return 0

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        """
        Collect Apache Log4j advisories from the CycloneDX VDR file.
        """
        xml_content = fetch_response(self.XML_URL).content
        if not xml_content:
            logger.error("No XML content fetched.")
            return []

        cleaned_xml_data = self._clean_xml_data(xml_content)
        if not cleaned_xml_data:
            logger.error("Failed to clean XML data")
            return []

        bom = Bom.from_xml(SafeElementTree.fromstring(cleaned_xml_data))

        for vulnerability in bom.vulnerabilities:
            if not vulnerability.id:
                continue

            yield from self._process_vulnerability(vulnerability)

    def _clean_xml_data(self, xml_content):
        """
        Clean XML data by removing XML schema instance attributes.
        """
        root = SafeElementTree.fromstring(xml_content)
        for elem in root.iter():
            attribs_to_remove = [
                k for k in elem.attrib if "{http://www.w3.org/2001/XMLSchema-instance}" in k
            ]
            for attrib in attribs_to_remove:
                del elem.attrib[attrib]
        return SafeElementTree.tostring(root, encoding="utf-8")

    def _process_vulnerability(self, vulnerability) -> Iterable[AdvisoryData]:
        """
        Process a single vulnerability and return AdvisoryData.
        """
        cve_id = vulnerability.id
        description = vulnerability.description or ""

        date_published = None
        if vulnerability.published:
            published_str = str(vulnerability.published)
            date_published = parse(published_str).replace(tzinfo=pytz.UTC)
        severities = []
        weaknesses = []
        for cwe in vulnerability.cwes:
            cwe_id = cwe
            weaknesses.append(get_cwe_id(f"CWE-{cwe_id}"))

        references = [
            Reference(url=f"https://nvd.nist.gov/vuln/detail/{cve_id}", reference_id=cve_id),
            Reference(url=f"{self.ASF_PAGE_URL}#{cve_id}", reference_id=cve_id),
        ]

        for rating in vulnerability.ratings:
            cvssv3_score = str(rating.score)
            cvssv3_vector = rating.vector
            cvssv3_url = str(rating.source.url)
            severities.append(
                VulnerabilitySeverity(
                    system=severity_systems.CVSSV3,
                    value=cvssv3_score,
                    scoring_elements=cvssv3_vector,
                )
            )
            references.append(Reference(url=cvssv3_url, severities=severities))

        fixed_versions = self._extract_fixed_versions(vulnerability.recommendation)
        affected_packages = self._get_affected_packages(vulnerability, fixed_versions)

        if affected_packages:
            yield AdvisoryData(
                aliases=[cve_id],
                summary=description,
                affected_packages=affected_packages,
                references=references,
                date_published=date_published,
                weaknesses=weaknesses,
                url=f"{self.ASF_PAGE_URL}#{cve_id}",
            )

    def _extract_fixed_versions(self, recommendation):
        """
        Extract fixed versions from recommendation text.
        """
        if not recommendation:
            return []

        recommendation_str = str(recommendation)
        version_pattern = r"\b(2\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9]+)?)\b"
        found_versions = re.findall(version_pattern, recommendation_str)

        valid_versions = [ver for ver in found_versions if ver in self.version_set]

        return list(dict.fromkeys(valid_versions))

    def _get_affected_packages(self, vulnerability, fixed_versions):
        """
        Get affected packages for a vulnerability.
        """
        version_groups = defaultdict(list)

        for vuln_target in vulnerability.affects:
            for version_range in vuln_target.versions:
                if version_range.version and not version_range.range:
                    self._process_single_version(version_range, fixed_versions, version_groups)
                elif version_range.range:
                    self._process_version_range(version_range, fixed_versions, version_groups)

        affected_packages = []
        for fixed_version, versions in version_groups.items():
            unique_versions = sorted(set(versions), key=lambda x: MavenVersion(x))
            version_range_str = f"vers:maven/{('|'.join(unique_versions))}"

            affected_packages.append(
                AffectedPackage(
                    package=PackageURL(
                        type="apache",
                        name="log4j-core",
                    ),
                    affected_version_range=version_range_str,
                    fixed_version=fixed_version,
                )
            )

        return affected_packages

    def _process_single_version(self, version_range, fixed_versions, version_groups):
        """
        Process a single version and add it to version groups.
        """
        current_version = version_range.version.replace("vers:maven/", "")
        fixed_version = next(
            (ver for ver in fixed_versions if MavenVersion(ver) >= MavenVersion(current_version)),
            None,
        )
        if fixed_version:
            version_groups[fixed_version].append(current_version)

    def _process_version_range(self, version_range, fixed_versions, version_groups):
        """
        Process a version range and add affected versions to version groups.
        """
        start_version, end_version = self._parse_version_range(version_range.range)
        if not start_version or not end_version:
            return

        affected_versions = self._get_versions_in_range(
            start_version, end_version, self.version_set
        )
        if not affected_versions:
            return

        fixed_version = self._get_fixed_version(fixed_versions, end_version)
        if fixed_version:
            version_groups[fixed_version].extend(affected_versions)

    def _parse_version_range(self, range_str):
        """
        Parse version range string and return start and end versions.
        """
        if re.match(r"^vers:maven/\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9]+)?$", range_str):
            single_version = range_str.replace("vers:maven/", "").strip()
            return single_version, single_version

        range_parts = range_str.replace("vers:maven/", "").split("|")

        if ">=" in range_parts[0] and "<" in range_parts[1]:
            start_version = range_parts[0].replace(">=", "").strip()
            end_version = range_parts[1].replace("<", "").strip()
            return start_version, end_version

        return None, None

    def _get_versions_in_range(self, start_version, end_version, version_set):
        """
        Get list of versions between start and end versions.
        """
        start_mv = MavenVersion(start_version)
        end_mv = MavenVersion(end_version)

        versions_in_range = [
            ver
            for ver in version_set
            if MavenVersion(ver) >= start_mv and MavenVersion(ver) < end_mv
        ]

        return versions_in_range

    def _get_fixed_version(self, fixed_versions, end_version):
        """
        Get appropriate fixed version for a given end version.
        """
        end_mv = MavenVersion(end_version)

        for fix_ver in fixed_versions:
            fix_mv = MavenVersion(fix_ver)
            if fix_mv >= end_mv:
                return fix_ver

        return None
