#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#

import re
import logging
from typing import List, Dict, Optional, Tuple

import requests
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData, Importer

logger = logging.getLogger(__name__)


class APKBUILDParser:
    """Parser for Alpine Linux APKBUILD files."""
    
    SECFIXES_START_PATTERN = re.compile(r'^\s*#\s*secfixes:\s*$', re.IGNORECASE)
    VERSION_PATTERN = re.compile(r'^\s*#\s+([0-9]+[^:]+):\s*$')
    CVE_PATTERN = re.compile(r'^\s*#\s+-\s+(CVE-\d{4}-\d+)\s*$', re.IGNORECASE)
    
    def parse_apkbuild_content(self, content: str) -> Dict[str, List[str]]:
        """Parse APKBUILD content and extract secfixes."""
        lines = content.split('\n')
        secfixes = {}
        in_secfixes_section = False
        current_version = None
        
        for line in lines:
            if self.SECFIXES_START_PATTERN.match(line):
                in_secfixes_section = True
                continue
            
            if in_secfixes_section:
                if not line.strip().startswith('#'):
                    in_secfixes_section = False
                    current_version = None
                    continue
                
                version_match = self.VERSION_PATTERN.match(line)
                if version_match:
                    current_version = version_match.group(1).strip()
                    secfixes[current_version] = []
                    continue
                
                if current_version:
                    cve_match = self.CVE_PATTERN.match(line)
                    if cve_match:
                        cve_id = cve_match.group(1).upper()
                        secfixes[current_version].append(cve_id)
        
        return secfixes
    
    def parse_apkbuild_url(self, url: str) -> Tuple[Optional[str], Dict[str, List[str]]]:
        """Fetch and parse APKBUILD from URL."""
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            content = response.text
            
            package_name = None
            url_parts = url.rstrip('/').split('/')
            if 'APKBUILD' in url_parts:
                idx = url_parts.index('APKBUILD')
                if idx > 0:
                    package_name = url_parts[idx - 1]
            
            secfixes = self.parse_apkbuild_content(content)
            return package_name, secfixes
            
        except requests.RequestException as e:
            logger.error(f"Failed to fetch APKBUILD from {url}: {e}")
            return None, {}


class AlpineImporter(Importer):
    """
    Importer for Alpine Linux security advisories from APKBUILD files.
    Addresses GitHub issue #509
    """
    
    spdx_license_expression = "MIT"
    license_url = "https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/LICENSE"
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.parser = APKBUILDParser()
    
    def advisory_data(self):
        """Yield AdvisoryData for Alpine Linux packages."""
        logger.info("AlpineImporter: Starting import")
        
        example_url = "https://git.alpinelinux.org/aports/plain/main/asterisk/APKBUILD"
        
        try:
            package_name, secfixes = self.parser.parse_apkbuild_url(example_url)
            
            if package_name and secfixes:
                logger.info(f"Processing {package_name} with {len(secfixes)} versions")
                
                cve_to_versions = {}
                for version, cve_list in secfixes.items():
                    for cve_id in cve_list:
                        if cve_id not in cve_to_versions:
                            cve_to_versions[cve_id] = []
                        cve_to_versions[cve_id].append(version)
                
                for cve_id, versions in cve_to_versions.items():
                    advisory = AdvisoryData(
                        aliases=[cve_id],
                        summary=f"{cve_id} fixed in {package_name}",
                        url=example_url,
                    )
                    yield advisory
                    
        except Exception as e:
            logger.error(f"Error processing Alpine package: {e}")