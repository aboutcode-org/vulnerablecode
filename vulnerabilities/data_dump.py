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


def debian_dump(extract_data):
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
        package = Package.objects.create(
            name=data.get('package_name', ''),
            version=data.get('fixed_version', ''),
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
                url='https://security.archlinux.org/{}'.format(vulnerability_id)
            )

        for package_name in packages_name:
            package_affected = Package.objects.create(
                name=package_name,
                version=affected_version
            )
            ImpactedPackage.objects.create(
                vulnerability=vulnerability,
                package=package_affected
            )
            PackageReference.objects.create(
                package=package_affected,
                repository='https://security.archlinux.org/package/{}'.format(package_name)
            )
            package_fixed = Package.objects.create(
                name=package_name,
                version=fixed_version
            )
            ResolvedPackage.objects.create(
                vulnerability=vulnerability,
                package=package_fixed
            )
            PackageReference.objects.create(
                package=package_fixed,
                repository='https://security.archlinux.org/package/{}'.format(package_name)
            )
