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

from vulncode_app.models import Vulnerability
from vulncode_app.models import VulnerabilityReference
from vulncode_app.models import ImpactedPackage
from vulncode_app.models import ResolvedPackage
from vulncode_app.models import Package
from vulncode_app.models import PackageReference

from scraper import debian
from scraper import ubuntu


def debian_dump():

    json_data = debian.json_data()
    extracted_data = debian.extract_data(json_data)

    for i, v in enumerate(extract_data):
        vulnerability = Vulnerability(summary=extract_data[i].get('description'))
        vulnerability_reference = VulnerabilityReference(
                                              reference_id=extract_data[i].get('vulnerability_id'))
        package = ImpactedPackage(name=extract_data[i].get('package'),
                                  version=extract_data[i].get('fixed_version'))

    vulnerability.save()
    vulnerability_reference.save()
    package.save()


def ubuntu_dump():

    data = ubuntu.scrape_cves()

    for i, v in enumerate(extract_data):
        vulnerability_reference = VulnerabilityReference(
                                              reference_id=data[i].get('cve_id'))
        package = ImpactedPackage(name=data[i].get('package_name'))

    vulnerability_reference.save()
    package.save()
