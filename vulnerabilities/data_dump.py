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
from vulnerabilities.models import PackageReference
from vulnerabilities.models import ResolvedPackage
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference


def debian_dump(extract_data, base_release='jessie'):
    """
    Save data scraped from Debian' security tracker.
    """
    for data in extract_data:
        vulnerability = Vulnerability.objects.create(
            summary=data.get('description', ''),
        )
        VulnerabilityReference.objects.create(
            vulnerability=vulnerability,
            reference_id=data.get('vulnerability_id', ''),
        )

        pkg_name = data.get('package_name', '')
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
        vulnerability = Vulnerability.objects.create(
            summary='',
        )
        VulnerabilityReference.objects.create(
            vulnerability=vulnerability,
            reference_id=data.get('cve_id'),
        )
        package = Package.objects.create(
            name=data.get('package_name'),
            type='deb',
            namespace='ubuntu'
        )
        ImpactedPackage.objects.create(
            vulnerability=vulnerability,
            package=package
        )


def archlinux_dump(extract_data):
    """
    Save data scraped from archlinux' security tracker.
    """
    for item in extract_data:
        cves = item['issues']
        group = item['name']

        advisories = set(item['advisories'])
        vulnerabilities = cves + list(advisories)
        vulnerabilities.append(group)
        packages_name = item['packages']

        affected_version = item['affected']
        fixed_version = item['fixed']
        if not fixed_version:
            fixed_version = 'None'

        vulnerability = Vulnerability.objects.create(
            summary=item['type'],
        )

        for vulnerability_id in vulnerabilities:
            VulnerabilityReference.objects.create(
                vulnerability=vulnerability,
                reference_id=vulnerability_id,
<<<<<<< HEAD
                url=f'https://security.archlinux.org/{vulnerability_id}',
=======
                url='https://security.archlinux.org/{}'.format(
                    vulnerability_id)
>>>>>>> fixed styling issue
            )

        for package_name in packages_name:
            package_affected = Package.objects.create(
                name=package_name,
                type='pacman',
                namespace='archlinux',
                version=affected_version
            )
            ImpactedPackage.objects.create(
                vulnerability=vulnerability,
                package=package_affected
            )
            PackageReference.objects.create(
                package=package_affected,
                repository=f'https://security.archlinux.org/package/{package_name}',
            )
            package_fixed = Package.objects.create(
                name=package_name,
                type='pacman',
                namespace='archlinux',
                version=fixed_version
            )
            ResolvedPackage.objects.create(
                vulnerability=vulnerability,
                package=package_fixed
            )
            PackageReference.objects.create(
                package=package_fixed,
                repository=f'https://security.archlinux.org/package/{package_name}',
            )


def npm_dump(extract_data):
    for data in extract_data:
        vulnerability = Vulnerability.objects.create(
            summary=data.get('summary'),
        )
        VulnerabilityReference.objects.create(
            vulnerability=vulnerability,
            reference_id=data.get('vulnerability_id'),
        )

        affected_versions = data.get('affected_version', [])
        for version in affected_versions:
            package_affected = Package.objects.create(
                name=data.get('package_name'),
                version=version,
            )
            ImpactedPackage.objects.create(
                vulnerability=vulnerability,
                package=package_affected
            )

        fixed_versions = data.get('fixed_version', [])
        for version in fixed_versions:
            package_fixed = Package.objects.create(
                name=data.get('package_name'),
                version=version
            )
            ResolvedPackage.objects.create(
                vulnerability=vulnerability,
                package=package_fixed
            )
