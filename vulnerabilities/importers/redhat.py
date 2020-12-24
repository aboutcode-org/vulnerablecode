# Copyright (c) nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software code from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.


import json

from packageurl import PackageURL
import requests

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.severity_systems import scoring_systems


class RedhatDataSource(DataSource):
    CONFIG_CLASS = DataSourceConfiguration

    def __enter__(self):
        self.redhat_response = fetch()

    def updated_advisories(self):
        processed_advisories = []
        for advisory_data in self.redhat_response:
            processed_advisories.extend(to_advisory(advisory_data))

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
        url = "https://bugzilla.redhat.com/show_bug.cgi?id={}".format(bugzilla)
        bugzilla_data = requests.get(f"https://bugzilla.redhat.com/rest/bug/{bugzilla}").json()
        bugzilla_severity_val = bugzilla_data["bugs"][0]["severity"]
        bugzilla_severity = VulnerabilitySeverity(
            system=scoring_systems["rhbs"],
            value=bugzilla_severity_val,
        )

        references.append(
            Reference(
                severities=[bugzilla_severity],
                url=url,
                reference_id=bugzilla,
            )
        )

    for rh_adv in advisory_data["advisories"]:
        # RH provides 3 types of advisories RHSA, RHBA, RHEA. Only RHSA's contain severity score.
        # See https://access.redhat.com/articles/2130961 for more details.

        if "RHSA" in rh_adv:
            rhsa_data = requests.get(f"https://access.redhat.com/hydra/rest/securitydata/cvrf/{rh_adv}.json").json()  # nopep8
            value = rhsa_data["cvrfdoc"]["aggregate_severity"]
            rhsa_aggregate_severity = VulnerabilitySeverity(
                system=scoring_systems["rhas"],
                value=value,
            )

            references.append(
                Reference(
                    severities=[rhsa_aggregate_severity],
                    url="https://access.redhat.com/errata/{}".format(rh_adv),
                    reference_id=rh_adv,
                )
            )

        else:
            references.append(Reference(severities=[], url=url, reference_id=rh_adv))

    redhat_cve_entry = requests.get(advisory_data["resource_url"]).json()
    redhat_cvss = redhat_cve_entry["cvss3"]["cvss3_base_score"]
    redhat_cvss3 = VulnerabilitySeverity(
        system=scoring_systems["rh_cvssv3"],
        value=redhat_cvss,
    )

    references.append(Reference(severities=[redhat_cvss3], url=advisory_data["resource_url"]))

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
