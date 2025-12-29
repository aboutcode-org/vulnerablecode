#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#

import json
import logging
import re
from typing import Iterable
from typing import Mapping

import requests
from packageurl import PackageURL
from univers.version_range import GenericVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import fetch_response

logger = logging.getLogger(__name__)


class APKBUILDParser:
    SECFIXES_START_PATTERN = re.compile(r'^\s*#\s*secfixes:\s*$', re.IGNORECASE)
    VERSION_PATTERN = re.compile(r'^\s*#\s+([0-9]+[^:]+):\s*$')
    CVE_PATTERN = re.compile(r'^\s*#\s+-\s+(CVE-\d{4}-\d+)\s*$', re.IGNORECASE)
    
    def parse_apkbuild_content(self, content: str) -> dict:
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
    
    def parse_apkbuild_url(self, url: str):
        try:
            response = fetch_response(url)
            content = response.text
            
            package_name = None
            url_parts = url.rstrip('/').split('/')
            if 'APKBUILD' in url_parts:
                idx = url_parts.index('APKBUILD')
                if idx > 0:
                    package_name = url_parts[idx - 1]
            
            secfixes = self.parse_apkbuild_content(content)
            return package_name, secfixes
            
        except Exception as e:
            logger.error(f"Failed to fetch APKBUILD from {url}: {e}")
            return None, {}


class AlpineLinuxImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "alpine_linux_importer_v2"
    spdx_license_expression = "MIT"
    license_url = "https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/LICENSE"
    
    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )
    
    def fetch(self) -> Iterable[Mapping]:
        self.log("Fetching Alpine Linux APKBUILD files")
        
        self.packages_data = []
        
        packages_to_process = [
            ('main', 'asterisk'),
        ]
        
        parser = APKBUILDParser()
        
        for branch, package in packages_to_process:
            url = f"https://git.alpinelinux.org/aports/plain/{branch}/{package}/APKBUILD"
            self.log(f"Fetching {url}")
            
            try:
                package_name, secfixes = parser.parse_apkbuild_url(url)
                if package_name and secfixes:
                    self.packages_data.append({
                        'package': package_name,
                        'branch': branch,
                        'secfixes': secfixes,
                        'url': url,
                    })
            except Exception as e:
                logger.error(f"Error processing {package}: {e}")
    
    def advisories_count(self) -> int:
        count = 0
        for package_data in self.packages_data:
            for cves in package_data['secfixes'].values():
                count += len(cves)
        return count
    
    def collect_advisories(self) -> Iterable[AdvisoryData]:
        """Collect advisories from fetched data."""
        for package_data in self.packages_data:
            yield from self.parse_package_advisories(package_data)
    
    def parse_package_advisories(self, package_data: Mapping) -> Iterable[AdvisoryData]:
        package_name = package_data['package']
        branch = package_data['branch']
        secfixes = package_data['secfixes']
        url = package_data['url']
        
        cve_to_versions = {}
        for version, cve_list in secfixes.items():
            for cve_id in cve_list:
                if cve_id not in cve_to_versions:
                    cve_to_versions[cve_id] = []
                cve_to_versions[cve_id].append(version)
        
        for cve_id, versions in cve_to_versions.items():
            affected_packages = []
            
            purl = PackageURL(
                type="apk",
                namespace=branch,
                name=package_name,
            )
            
            affected_package = AffectedPackageV2(
                package=purl,
                fixed_version_range=GenericVersionRange.from_versions(versions),
            )
            affected_packages.append(affected_package)
            
            references = [
                ReferenceV2(
                    reference_id=f"alpine-{branch}-{package_name}",
                    url=url,
                ),
                ReferenceV2(
                    reference_id=cve_id,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                ),
            ]
            
            yield AdvisoryData(
                advisory_id=f"alpine-{branch}-{package_name}-{cve_id}",
                aliases=[cve_id],
                summary=f"{cve_id} fixed in {package_name}",
                affected_packages=affected_packages,
                references_v2=references,
                url=url,
                weaknesses=[],
                original_advisory_text=json.dumps(
                    {
                        'package': package_name,
                        'branch': branch,
                        'cve': cve_id,
                        'fixed_versions': versions,
                    },
                    indent=2,
                ),
            )