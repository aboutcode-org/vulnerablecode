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

import requests
from packageurl import PackageURL

from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.helpers import requests_with_5xx_retry
from vulnerabilities.severity_systems import scoring_systems


class RedhatImporter(Importer):
    def __enter__(self):

        self.redhat_cves = fetch()

    def updated_advisories(self):
        processed_advisories = list(map(to_advisory, self.redhat_cves))
        return self.batch_advisories(processed_advisories)


requests_session = requests_with_5xx_retry(max_retries=5, backoff_factor=1)


def fetch():
    """
    Return a list of CVE data mappings fetched from the RedHat API.
    See:
        https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/index
    """
    cves = []
    page_no = 1
    url_template = "https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=10000&page={}"  # nopep8

    cve_data = None
    while True:
        current_url = url_template.format(page_no)
        try:
            print(f"Fetching: {current_url}")
            response = requests_session.get(current_url)
            if response.status_code != requests.codes.ok:
                # TODO: log me
                print(f"Failed to fetch results from {current_url}")
                break
            cve_data = response.json()
        except Exception as e:
            # TODO: log me
            msg = f"Failed to fetch results from {current_url}:\n{e}"
            print(msg)
            break

        if not cve_data:
            break
        cves.extend(cve_data)
        page_no += 1

    return cves


def to_advisory(advisory_data):
    affected_purls = []
    if advisory_data.get("affected_packages"):
        for rpm in advisory_data["affected_packages"]:
            purl = rpm_to_purl(rpm)
            if purl:
                affected_purls.append(purl)

    references = []
    bugzilla = advisory_data.get("bugzilla")
    if bugzilla:
        url = "https://bugzilla.redhat.com/show_bug.cgi?id={}".format(bugzilla)
        bugzilla_data = requests_session.get(
            f"https://bugzilla.redhat.com/rest/bug/{bugzilla}"
        ).json()
        if (
            bugzilla_data.get("bugs")
            and len(bugzilla_data["bugs"])
            and bugzilla_data["bugs"][0].get("severity")
        ):
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

        if "RHSA" in rh_adv.upper():
            rhsa_data = requests_session.get(
                f"https://access.redhat.com/hydra/rest/securitydata/cvrf/{rh_adv}.json"
            ).json()  # nopep8

            rhsa_aggregate_severities = []
            if rhsa_data.get("cvrfdoc"):
                # not all RHSA errata have a corresponding CVRF document
                value = rhsa_data["cvrfdoc"]["aggregate_severity"]
                rhsa_aggregate_severities.append(
                    VulnerabilitySeverity(
                        system=scoring_systems["rhas"],
                        value=value,
                    )
                )

            references.append(
                Reference(
                    severities=rhsa_aggregate_severities,
                    url="https://access.redhat.com/errata/{}".format(rh_adv),
                    reference_id=rh_adv,
                )
            )

        else:
            references.append(Reference(severities=[], url=url, reference_id=rh_adv))

    redhat_scores = []
    cvssv3_score = advisory_data.get("cvss3_score")
    if cvssv3_score:
        redhat_scores.append(
            VulnerabilitySeverity(
                system=scoring_systems["cvssv3"],
                value=cvssv3_score,
            )
        )

    cvssv3_vector = advisory_data.get("cvss3_scoring_vector")
    if cvssv3_vector:
        redhat_scores.append(
            VulnerabilitySeverity(
                system=scoring_systems["cvssv3_vector"],
                value=cvssv3_vector,
            )
        )

    references.append(Reference(severities=redhat_scores, url=advisory_data["resource_url"]))
    return Advisory(
        vulnerability_id=advisory_data["CVE"],
        summary=advisory_data["bugzilla_description"],
        affected_packages=nearest_patched_package(affected_purls, []),
        references=references,
    )


def rpm_to_purl(rpm_string):
    # FIXME: there is code in scancode to handle RPM conversion AND this should
    # be all be part of the packageurl library

    # Red Hat uses `-:0` instead of just `-` to separate
    # package name and version
    components = rpm_string.split("-0:")
    if len(components) != 2:
        return

    name, version = components

    if version[0].isdigit():
        return PackageURL(namespace="redhat", name=name, type="rpm", version=version)
