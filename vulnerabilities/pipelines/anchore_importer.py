#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from typing import Iterable, List, Dict, Any, Optional
import logging

import requests
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline


logger = logging.getLogger(__name__)


class AnchoreImporterPipeline(VulnerableCodeBaseImporterPipeline):

    pipeline_id = "anchore_importer"
    root_url = "https://github.com/anchore/nvd-data-overrides"
    license_url = "https://github.com/anchore/nvd-data-overrides/blob/main/LICENSE"
    spdx_license_expression = "CC0-1.0"  
    importer_name = "Anchore NVD Overrides Importer"

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    def advisories_count(self) -> int:
        """Return the count of all advisories available from the data source."""
        data_dirs = self._get_data_directories()
        count = 0
        for dir_url in data_dirs:
            files = self._get_json_files(dir_url)
            count += len(files)
        return count

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        """Collect advisory data from the Anchore NVD Data Overrides repository."""
        data_dirs = self._get_data_directories()
        for dir_url in data_dirs:
            files = self._get_json_files(dir_url)
            for file_url in files:
                try:
                    raw_data = self._fetch_json_data(file_url)
                    if raw_data:
                        advisory = self.parse_advisory_data(raw_data)
                        if advisory:
                            yield advisory
                except Exception as e:
                    logger.error(f"Error processing file {file_url}: {e}")

    def _get_data_directories(self) -> List[str]:
        """Get the list of year directories in the data folder."""
        contents_url = "https://api.github.com/repos/anchore/nvd-data-overrides/contents/data"
        response = requests.get(contents_url)
        response.raise_for_status()
        
        contents = response.json()
        return [
            item["url"] 
            for item in contents 
            if item["type"] == "dir"
        ]

    def _get_json_files(self, dir_url: str) -> List[str]:
        """Get the list of JSON files in a directory."""
        response = requests.get(dir_url)
        response.raise_for_status()
        
        contents = response.json()
        return [
            item["download_url"] 
            for item in contents 
            if item["type"] == "file" and item["name"].endswith(".json")
        ]

    def _fetch_json_data(self, file_url: str) -> Dict[str, Any]:
        """Fetch and parse JSON data from a file URL."""
        response = requests.get(file_url)
        response.raise_for_status()
        return response.json()

    def _extract_cpe_details(self, cpe_string: str) -> Optional[Dict[str, str]]:
        """Extract vendor and product information from a CPE string.
        
        Example CPE: cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*
        """
        parts = cpe_string.split(":")
        if len(parts) < 6:
            return None
        
        return {
            "vendor": parts[3],
            "product": parts[4],
        }

    def parse_advisory_data(self, raw_data: Dict[str, Any]) -> Optional[AdvisoryData]:
        """Parse advisory data from the JSON data structure."""
        # Extract CVE ID from _annotation
        annotation = raw_data.get("_annotation", {})
        cve_id = annotation.get("cve_id")
        if not cve_id:
            return None

        # Extract summary/reason from _annotation
        summary = annotation.get("reason", "")
        
        # Extract source reference
        references = []
        source_url = annotation.get("generated_from")
        if source_url:
            references.append(Reference(url=source_url))
        
        # Add repository URL as a reference
        references.append(Reference(url=self.root_url))
        
        # Extract affected packages from CPE matching information
        affected_packages = []
        
        try:
            # Navigate through the nested structure to get to CPE matches
            for config in raw_data.get("cve", {}).get("configurations", []):
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        # Only process if marked as vulnerable
                        if not cpe_match.get("vulnerable", False):
                            continue
                        
                        # Extract CPE information
                        criteria = cpe_match.get("criteria")
                        if not criteria:
                            continue
                        
                        cpe_details = self._extract_cpe_details(criteria)
                        if not cpe_details:
                            continue
                        
                        # Create package URL
                        purl = PackageURL(
                            type="generic", 
                            namespace=cpe_details["vendor"], 
                            name=cpe_details["product"]
                        )
                        
                        # Extract version constraints
                        version_constraints = {}
                        if "versionStartIncluding" in cpe_match:
                            version_constraints["min"] = cpe_match["versionStartIncluding"]
                            version_constraints["min_included"] = True
                        elif "versionStartExcluding" in cpe_match:
                            version_constraints["min"] = cpe_match["versionStartExcluding"]
                            version_constraints["min_included"] = False
                            
                        if "versionEndIncluding" in cpe_match:
                            version_constraints["max"] = cpe_match["versionEndIncluding"]
                            version_constraints["max_included"] = True
                        elif "versionEndExcluding" in cpe_match:
                            version_constraints["max"] = cpe_match["versionEndExcluding"]
                            version_constraints["max_included"] = False
                        
                        # Create version range string based on constraints
                        if version_constraints:
                            range_parts = []
                            
                            if "min" in version_constraints:
                                operator = ">=" if version_constraints.get("min_included", False) else ">"
                                range_parts.append(f"{operator}{version_constraints['min']}")
                                
                            if "max" in version_constraints:
                                operator = "<=" if version_constraints.get("max_included", False) else "<"
                                range_parts.append(f"{operator}{version_constraints['max']}")
                            
                            affected_version_range = ",".join(range_parts)
                            
                            affected_package = AffectedPackage(
                                package=purl,
                                affected_version_range=affected_version_range,
                                fixed_version=None,  # No explicit fixed version in this format
                            )
                            affected_packages.append(affected_package)
        except Exception as e:
            logger.error(f"Error parsing CPE data for {cve_id}: {e}")
        
        # If we couldn't extract any package information, return None
        if not affected_packages:
            logger.warning(f"No affected packages found for {cve_id}")
            return None
        
        # Create and return the advisory data
        return AdvisoryData(
            aliases=[cve_id],
            summary=summary,
            affected_packages=affected_packages,
            references=references,
            date_published=None,  # No publication date in this format
        )