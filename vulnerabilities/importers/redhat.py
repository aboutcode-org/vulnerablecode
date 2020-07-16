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

import requests

from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import VulnerabilityReferenceUnit


class RedhatDataSource(DataSource):
    CONFIG_CLASS = DataSourceConfiguration

    def __enter__(self):

        self.redhat_response = fetch()

    def updated_advisories(self):
        processed_advisories = []
        for advisory_data in self.redhat_response:
            processed_advisories.append(to_advisory(advisory_data))

        return self.batch_advisories(processed_advisories)


def fetch():

    response = []
    page_no = 1
    url = "https://access.redhat.com/hydra/rest/securitydata/cve.json?page={}"

    while True:

        resp_json = requests.get(url.format(page_no)).json()
        page_no += 1
        if not resp_json:
            break

        for advisory in resp_json:
            response.append(advisory)

    return response


def to_advisory(advisory_data):

    affected_purls = []
    if advisory_data.get("affected_packages"):
        for rpm in advisory_data["affected_packages"]:
            if rpm_to_purl(rpm):
                affected_purls.append(rpm_to_purl(rpm))

    references = []
    if advisory_data.get("bugzilla"):
        bugzilla = advisory_data.get("bugzilla")
        references.append(
            VulnerabilityReferenceUnit(
                url="https://bugzilla.redhat.com/show_bug.cgi?id={}".format(bugzilla),
                reference_id=bugzilla,
            )
        )

    for rhsa in advisory_data["advisories"]:
        references.append(
            VulnerabilityReferenceUnit(
                url="https://access.redhat.com/errata/{}".format(rhsa), reference_id=rhsa,
            )
        )

    references.append(VulnerabilityReferenceUnit(url=advisory_data["resource_url"]))

    return Advisory(
        summary=advisory_data["bugzilla_description"],
        cve_id=advisory_data["CVE"],
        impacted_package_urls=affected_purls,
        vuln_references=references,
    )


def rpm_to_purl(rpm_string):

    # Red Hat uses `-:0` instead of just `-` to separate
    # package name and version
    components = rpm_string.split("-0:")
    if len(components) != 2:
        return

    name, version = components

    if version[0].isdigit():
        return PackageURL(name=name, type="rpm", version=version, namespace="redhat")
