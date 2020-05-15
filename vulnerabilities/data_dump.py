#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import Package
from vulnerabilities.models import ResolvedPackage
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference


def debian_dump(extract_data, base_release='jessie'):
    """
    Save data scraped from Debian' security tracker.
    """
    for data in extract_data:
        vulnerability, _ = Vulnerability.objects.get_or_create(
            cve_id=data['cve_id'],
        )

        pkg_name = data['package_name']
        package = Package.objects.create(
            name=pkg_name,
            type='deb',
            namespace='debian',
            version=data.get('version', ''),
            qualifiers=f'distro={base_release}',
        )

        if data['status'] == 'open':
            ImpactedPackage.objects.create(
                vulnerability=vulnerability,
                package=package
            )
        else:
            ResolvedPackage.objects.create(
                vulnerability=vulnerability,
                package=package
            )

            fixed_version = data.get('fixed_version')
            if fixed_version:
                package = Package.objects.create(
                    name=pkg_name,
                    type='deb',
                    namespace='debian',
                    version=fixed_version,
                    qualifiers=f'distro={base_release}',
                )

                ResolvedPackage.objects.create(
                    vulnerability=vulnerability,
                    package=package
                )


def ubuntu_dump(html):
    """
    Dump data scraped from Ubuntu's security tracker.
    """
    for data in html:
        vulnerability, _ = Vulnerability.objects.get_or_create(
            cve_id=data['cve_id'],
        )
        package = Package.objects.create(
            name=data['package_name'],
            type='deb',
            namespace='ubuntu'
        )
        ImpactedPackage.objects.create(
            vulnerability=vulnerability,
            package=package
        )


def npm_dump(extract_data):
    for data in extract_data:
        package_name = data['package_name']
        advisory = data['advisory']

        for cve_id in data['cve_ids']:
            vulnerability, _ = Vulnerability.objects.get_or_create(
                cve_id=cve_id,
            )

            if advisory:
                VulnerabilityReference.objects.create(
                    vulnerability=vulnerability,
                    url=advisory,
                )

            for version in data['affected_versions']:
                package_affected = Package.objects.create(
                    name=package_name,
                    type='npm',
                    version=version,
                )
                ImpactedPackage.objects.create(
                    vulnerability=vulnerability,
                    package=package_affected
                )

            for version in data['fixed_versions']:
                package_fixed = Package.objects.create(
                    name=package_name,
                    type='npm',
                    version=version
                )
                ResolvedPackage.objects.create(
                    vulnerability=vulnerability,
                    package=package_fixed
                )


def ruby_dump(extract_data):
    for package_data in extract_data:

        vulnerability, _ = Vulnerability.objects.get_or_create(
            cve_id=package_data['cve_id']
        )

        VulnerabilityReference.objects.get_or_create(
            vulnerability=vulnerability,
            url=package_data['advisory']
        )

        for version in package_data['affected_versions']:
            affected_package = Package.objects.create(
                name=package_data['package_name'],
                type='gem',
                version=version
            )
            ImpactedPackage.objects.create(
                vulnerability=vulnerability,
                package=affected_package
            )

        for version in package_data['fixed_versions']:
            unaffected_package = Package.objects.create(
                name=package_data['package_name'],
                type='gem',
                version=version
            )
            ResolvedPackage.objects.create(
                vulnerability=vulnerability,
                package=unaffected_package
            )


def safetydb_dump(extract_data):
    for package_data in extract_data:
        for cve_id in package_data['cve_id']:
            vulnerability, _ = Vulnerability.objects.get_or_create(
                summary=package_data['description'],
                cve_id=cve_id
            )

        VulnerabilityReference.objects.get_or_create(
            vulnerability=vulnerability,
            reference_id=package_data['vuln_id']
        )

        for version in package_data['affected_versions']:
            affected_package = Package.objects.create(
                name=package_data['package_name'],
                type='pypi',
                version=version
            )
            ImpactedPackage.objects.create(
                vulnerability=vulnerability,
                package=affected_package
            )

        for version in package_data['unaffected_versions']:
            unaffected_package = Package.objects.create(
                name=package_data['package_name'],
                type='pypi',
                version=version
            )
            ResolvedPackage.objects.create(
                vulnerability=vulnerability,
                package=unaffected_package
            )
