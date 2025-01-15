import logging
import xml.etree.ElementTree as ET

import pytz
import requests
from dateutil.parser import parse
from packageurl import PackageURL
from univers.version_range import MavenVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference

logger = logging.getLogger(__name__)


class ApacheLog4jImporter(Importer):
    XML_URL = "https://logging.apache.org/cyclonedx/vdr.xml"
    ASF_PAGE_URL = "https://logging.apache.org/security.html"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/"
    importer_name = "Apache Log4j Importer"

    @staticmethod
    def fetch_advisory_page():
        """
        Fetch the Log4j vulnerability XML feed.
        """
        try:
            response = requests.get(ApacheLog4jImporter.XML_URL, timeout=30)
            response.raise_for_status()
            return response.content
        except requests.RequestException as e:
            logger.error(f"Failed to fetch Log4j vulnerability data: {e}")
            return None

    @staticmethod
    def parse_version_range(range_str):
        """
        Parse version range string and return start and end versions.
        Example: "vers:maven/>=2.0-beta7|<2.3.2" -> ("2.0-beta7", "2.3.2")
        """
        try:
            range_parts = range_str.replace("vers:maven/", "").split("|")
            start_version = range_parts[0].replace(">=", "").strip()
            end_version = range_parts[1].replace("<", "").strip()
            return start_version, end_version
        except Exception as e:
            logger.error(f"Error parsing version range {range_str}: {e}")
            return None, None

    @staticmethod
    def get_versions_in_range(start_version, end_version, version_mapping):
        """
        Get all versions between start_version and end_version from version_mapping.
        """
        try:
            start_idx = version_mapping.index(start_version)
            end_idx = version_mapping.index(end_version)
            return version_mapping[start_idx:end_idx]
        except ValueError as e:
            logger.error(f"Error getting versions in range: {e}")
            return []

    def to_advisory(self, xml_content):
        """
        Parse the XML content and create AdvisoryData objects.
        """
        advisories = []
        version_mapping = [
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

        try:
            root = ET.fromstring(xml_content)
            ns = {"ns0": "http://cyclonedx.org/schema/bom/1.5"}
            vulnerabilities = root.findall(".//ns0:vulnerability", ns)

            for vuln in vulnerabilities:
                cve_id = vuln.find("./ns0:id", ns)
                if cve_id is None or not cve_id.text:
                    continue
                cve_id = cve_id.text.strip()

                description = vuln.find("./ns0:description", ns)
                description_text = description.text.strip() if description is not None else ""

                published_date_text = vuln.find("./ns0:published", ns)
                date_published = None
                if published_date_text is not None and published_date_text.text:
                    try:
                        date_published = parse(published_date_text.text.strip()).replace(
                            tzinfo=pytz.UTC
                        )
                    except ValueError as e:
                        logger.error(f"Error parsing date {published_date_text.text}: {e}")

                references = [
                    Reference(
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}", reference_id=cve_id
                    ),
                    Reference(url=f"{self.ASF_PAGE_URL}#{cve_id}", reference_id=cve_id),
                ]

                affected_packages = self.get_affected_packages(vuln, version_mapping)

                advisories.append(
                    AdvisoryData(
                        aliases=[cve_id],
                        summary=description_text,
                        affected_packages=affected_packages,
                        references=references,
                        date_published=date_published,
                        url=f"{self.ASF_PAGE_URL}#{cve_id}",
                    )
                )
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML content: {e}")

        return advisories

    def get_affected_packages(self, vuln, version_mapping):
        """
        Extract affected packages from the vulnerability element.
        """
        ns = {"ns0": "http://cyclonedx.org/schema/bom/1.5"}
        affected_packages = []

        recommendation = vuln.find(".//ns0:recommendation", ns)
        fixed_versions = []
        if recommendation is not None and recommendation.text:
            fixed_versions = [
                v.strip("`")
                for v in recommendation.text.split("`")
                if v.strip().replace(".", "").replace("-", "").isalnum()
            ]

        targets = vuln.findall(".//ns0:target", ns)
        for target in targets:
            ref = target.find("./ns0:ref", ns)
            if ref is None or not ref.text:
                continue

            version_ranges = target.findall("./ns0:versions/ns0:version/ns0:range", ns)
            for version_range in version_ranges:
                if version_range is None or not version_range.text:
                    continue

                start_version, end_version = self.parse_version_range(version_range.text.strip())
                if not start_version or not end_version:
                    continue

                affected_versions = self.get_versions_in_range(
                    start_version, end_version, version_mapping
                )
                if not affected_versions:
                    continue

                fixed_version = self.get_fixed_version(fixed_versions, end_version, version_mapping)
                if not fixed_version:
                    continue

                for affected_version in affected_versions:
                    affected_package = AffectedPackage(
                        package=PackageURL(
                            type="apache",
                            name="log4j-core",
                        ),
                        affected_version_range=MavenVersionRange.from_string(
                            f"vers:maven/{affected_version}"
                        ),
                        fixed_version=fixed_version,
                    )
                    affected_packages.append(affected_package)

        return affected_packages

    @staticmethod
    def get_fixed_version(fixed_versions, end_version, version_mapping):
        """
        Get the fixed version from the list of fixed versions.
        """
        for fix_ver in fixed_versions:
            if fix_ver in version_mapping and version_mapping.index(
                fix_ver
            ) >= version_mapping.index(end_version):
                return fix_ver
        return None

    def advisory_data(self):
        """
        Fetch advisory data and convert it into AdvisoryData objects.
        """
        xml_content = self.fetch_advisory_page()
        if not xml_content:
            logger.error("No XML content fetched.")
            return []

        advisories = self.to_advisory(xml_content)
        return advisories
