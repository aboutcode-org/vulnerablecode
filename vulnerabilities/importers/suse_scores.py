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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.helpers import fetch_yaml
from vulnerabilities.severity_systems import scoring_systems

URL = "https://ftp.suse.com/pub/projects/security/yaml/suse-cvss-scores.yaml"


class SUSESeverityScoreDataSource(DataSource):

    def updated_advisories(self):
        advisories = []
        score_data = fetch_yaml(URL)
        advisories.append(self.to_advisory(score_data))
        return advisories

    @staticmethod
    def to_advisory(score_data):
        advisories = []
        for cve_id in score_data:
            severities = []
            for cvss_score in score_data[cve_id]["cvss"]:
                score = None
                vector = None
                if cvss_score["version"] == 2.0:
                    score = VulnerabilitySeverity(
                        system=scoring_systems["cvssv2"],
                        value=str(cvss_score["score"])
                    )
                    vector = VulnerabilitySeverity(
                        system=scoring_systems["cvssv2_vector"],
                        value=str(cvss_score["vector"])
                    )

                elif cvss_score["version"] == 3:
                    score = VulnerabilitySeverity(
                        system=scoring_systems["cvssv3"],
                        value=str(cvss_score["score"])
                    )
                    vector = VulnerabilitySeverity(
                        system=scoring_systems["cvssv3_vector"],
                        value=str(cvss_score["vector"])
                    )

                elif cvss_score["version"] == 3.1:
                    score = VulnerabilitySeverity(
                        system=scoring_systems["cvssv3.1"],
                        value=str(cvss_score["score"])
                    )
                    vector = VulnerabilitySeverity(
                        system=scoring_systems["cvssv3.1_vector"],
                        value=str(cvss_score["vector"])
                    )

                severities.extend([score, vector])

            advisories.append(
                Advisory(
                    cve_id=cve_id,
                    summary="",
                    impacted_package_urls=[],
                    vuln_references=[
                        Reference(
                            url=URL,
                            severities=severities
                        )
                    ]
                )
            )
        return advisories
