import logging
import re
from typing import Iterable, List, Optional
from urllib.parse import urljoin

import requests
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData, AffectedPackage, Importer, Reference
from vulnerabilities.utils import nearest_patched_package

logger = logging.getLogger(__name__)


class AlpineImporter(Importer):
    spdx_license_expression = "MIT"
    license_url = "https://gitlab.alpinelinux.org/alpine/aports/-/blob/master/LICENSE"
    
    # Alpine Git repository base URL
    ALPINE_GIT_BASE = "https://git.alpinelinux.org/aports/tree/"
    
    # Regex patterns for parsing APKBUILD secfixes
    SECFIXES_START = re.compile(r'^\s*#\s*secfixes:\s*$', re.IGNORECASE)
    VERSION_LINE = re.compile(r'^\s*#\s+([0-9]+[^:]+):\s*$')
    CVE_LINE = re.compile(r'^\s*#\s+-\s+(CVE-\d{4}-\d+)\s*$', re.IGNORECASE)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # List of packages to process - this would typically come from crawling
        # the Alpine repository or a configuration file
        self.packages_to_process = []
    
    def advisory_data(self) -> Iterable[AdvisoryData]:
        # In a real implementation, you would:
        # 1. Fetch the list of all packages from Alpine repositories
        # 2. For each package, fetch its APKBUILD file
        # 3. Parse the secfixes section
        
        # For now, this demonstrates the structure with a known example
        example_packages = [
            ('main', 'asterisk', '9d426cf7a7701ee6707224d3e9f6d07553a56de1'),
        ]
        
        for branch, package, commit in example_packages:
            try:
                url = self._get_apkbuild_url(branch, package, commit)
                secfixes = self._parse_apkbuild_from_url(url)
                
                # Group by CVE to create advisories
                cve_to_versions = self._group_by_cve(secfixes)
                
                for cve_id, versions in cve_to_versions.items():
                    advisory = self._create_advisory(
                        cve_id=cve_id,
                        package_name=package,
                        fixed_versions=versions,
                        branch=branch,
                        apkbuild_url=url
                    )
                    yield advisory
                    
            except Exception as e:
                logger.error(f"Error processing {package} from {branch}: {e}")
                continue
    
    def _get_apkbuild_url(self, branch: str, package: str, commit: Optional[str] = None) -> str:
        """Construct URL to an APKBUILD file."""
        url = f"{self.ALPINE_GIT_BASE}{branch}/{package}/APKBUILD"
        if commit:
            url += f"?id={commit}"
        return url
    
    def _parse_apkbuild_from_url(self, url: str) -> dict:
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return self._parse_secfixes(response.text)
        except requests.RequestException as e:
            logger.error(f"Failed to fetch APKBUILD from {url}: {e}")
            return {}
    
    def _parse_secfixes(self, content: str) -> dict:
        lines = content.split('\n')
        secfixes = {}
        in_secfixes_section = False
        current_version = None
        
        for line in lines:
            # Check if we're entering the secfixes section
            if self.SECFIXES_START.match(line):
                in_secfixes_section = True
                continue
            
            if in_secfixes_section:
                # Check if we've left the secfixes section
                if not line.strip().startswith('#'):
                    break
                
                # Check for version line
                version_match = self.VERSION_LINE.match(line)
                if version_match:
                    current_version = version_match.group(1).strip()
                    secfixes[current_version] = []
                    continue
                
                # Check for CVE line
                if current_version:
                    cve_match = self.CVE_LINE.match(line)
                    if cve_match:
                        cve_id = cve_match.group(1).upper()
                        secfixes[current_version].append(cve_id)
        
        return secfixes
    
    def _group_by_cve(self, secfixes: dict) -> dict:
        cve_to_versions = {}
        for version, cve_list in secfixes.items():
            for cve_id in cve_list:
                if cve_id not in cve_to_versions:
                    cve_to_versions[cve_id] = []
                cve_to_versions[cve_id].append(version)
        return cve_to_versions
    
    def _create_advisory(
        self,
        cve_id: str,
        package_name: str,
        fixed_versions: List[str],
        branch: str,
        apkbuild_url: str
    ) -> AdvisoryData:
        # Create references
        references = [
            Reference(
                url=apkbuild_url,
                reference_id=f"alpine-{branch}-{package_name}",
            )
        ]
        
        # Add NVD reference for the CVE
        references.append(
            Reference(
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                reference_id=cve_id,
                severities=[],
            )
        )
        
        # Create affected packages (all versions before the fix are affected)
        # In a real implementation, you would need to determine the actual
        # affected version range. For now, we mark the fixed versions.
        affected_packages = []
        for fixed_version in fixed_versions:
            purl = PackageURL(
                type="alpine",
                namespace=branch,
                name=package_name,
                version=fixed_version,
            )
            
            affected_package = AffectedPackage(
                package=purl,
                fixed_version=fixed_version,
            )
            affected_packages.append(affected_package)
        
        return AdvisoryData(
            aliases=[cve_id],
            summary=f"{cve_id} fixed in {package_name} {', '.join(fixed_versions)}",
            affected_packages=affected_packages,
            references=references,
            url=apkbuild_url,
        )


class AlpineAPKBUILDCrawler:

    ALPINE_PACKAGES_API = "https://pkgs.alpinelinux.org/packages"
    
    def get_all_packages(self, branch: str = "main") -> List[str]:
        # This is a placeholder - actual implementation would need to:
        # 1. Query Alpine's package API or
        # 2. Clone the aports repository and find all APKBUILD files or
        # 3. Use the Alpine package database
        
        # Example packages that are known to have secfixes
        known_packages = [
            'asterisk',
            'expat',
            'openssl',
            'python3',
            'nginx',
            'apache2',
        ]
        
        return known_packages


# Example test function
def test_alpine_importer():
    """Test the Alpine importer with a known APKBUILD file."""
    importer = AlpineImporter()
    
    print("Testing Alpine APKBUILD Importer")
    print("=" * 60)
    
    advisories = list(importer.advisory_data())
    
    print(f"\nFound {len(advisories)} advisories")
    
    for advisory in advisories:
        print(f"\nAdvisory: {advisory.aliases}")
        print(f"  Summary: {advisory.summary}")
        print(f"  URL: {advisory.url}")
        print(f"  Affected packages: {len(advisory.affected_packages)}")
        for pkg in advisory.affected_packages:
            print(f"    - {pkg.package} (fixed in {pkg.fixed_version})")
        print(f"  References: {len(advisory.references)}")


if __name__ == '__main__':
    test_alpine_importer()