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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference


def normalized_reference(reference):
    severities = sorted(
        reference.severities, key=lambda severity: (severity.value, severity.system.identifier)
    )

    return Reference(reference_id=reference.reference_id, url=reference.url, severities=severities)


def normalized_advisory(advisory):
    impacted_package_urls = {package_url for package_url in advisory.impacted_package_urls}
    resolved_package_urls = {package_url for package_url in advisory.resolved_package_urls}
    vuln_references = sorted(
        advisory.vuln_references, key=lambda reference: (reference.reference_id, reference.url)
    )
    for index, _ in enumerate(advisory.vuln_references):
        vuln_references[index] = normalized_reference(vuln_references[index])

    return Advisory(
        summary=advisory.summary,
        vulnerability_id=advisory.vulnerability_id,
        impacted_package_urls=impacted_package_urls,
        resolved_package_urls=resolved_package_urls,
        vuln_references=vuln_references,
    )


# This is not entirely correct, but enough for testing purpose.
def advisory_sort_key(advisory):
    return advisory.vulnerability_id


def advisories_are_equal(expected_advisories, found_advisories):

    expected_advisories = list(filter(lambda x: isinstance(x, Advisory), expected_advisories))
    expected_advisories.sort(key=advisory_sort_key)
    expected_advisories = list(map(normalized_advisory, expected_advisories))

    found_advisories = list(filter(lambda x: isinstance(x, Advisory), found_advisories))
    found_advisories.sort(key=advisory_sort_key)
    found_advisories = list(map(normalized_advisory, found_advisories))

    return expected_advisories == found_advisories
