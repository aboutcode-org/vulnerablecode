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

import dataclasses

"""
Vulnerability scoring systems define scales, values and approach to score a
vulnerability severity.
"""


@dataclasses.dataclass(order=True)
class ScoringSystem:

    # a short identifier for the scoring system.
    identifier: str
    # a name which represents the scoring system such as `RedHat bug severity`.
    # This is for human understanding
    name: str
    # a url to documentation about that sscoring system
    url: str
    # notes about that scoring system
    notes: str = ""

    def as_score(self, value):
        """
        Return a normalized numeric score for this scoring system  given a raw
        value. For instance this can be used to convert a CVSS vector to a base
        score.
        """
        raise NotImplementedError


CVSSV2 = ScoringSystem(
    identifier="cvssv2",
    name="CVSSv2 Base Score",
    url="https://www.first.org/cvss/v2/",
    notes="cvssv2 base score",
)

CVSSV2_VECTOR = ScoringSystem(
    identifier="cvssv2_vector",
    name="CVSSv2 Vector",
    url="https://www.first.org/cvss/v2/",
    notes="cvssv2 vector, used to get additional info about "
    "nature and severity of vulnerability",
)

CVSSV3 = ScoringSystem(
    identifier="cvssv3",
    name="CVSSv3 Base Score",
    url="https://www.first.org/cvss/v3-0/",
    notes="cvssv3 base score",
)

CVSSV3_VECTOR = ScoringSystem(
    identifier="cvssv3_vector",
    name="CVSSv3 Vector",
    url="https://www.first.org/cvss/v3-0/",
    notes="cvssv3 vector, used to get additional info about "
    "nature and severity of vulnerability",
)

CVSSV31 = ScoringSystem(
    identifier="cvssv3.1",
    name="CVSSv3.1 Base Score",
    url="https://www.first.org/cvss/v3-1/",
    notes="cvssv3.1 base score",
)

CVSSV31_VECTOR = ScoringSystem(
    identifier="cvssv3.1_vector",
    name="CVSSv3.1 Vector",
    url="https://www.first.org/cvss/v3-1/",
    notes="cvssv3.1 vector, used to get additional info about "
    "nature and severity of vulnerability",
)

REDHAT_BUGZILLA = ScoringSystem(
    identifier="rhbs",
    name="RedHat Bugzilla severity",
    url="https://bugzilla.redhat.com/page.cgi?id=fields.html#bug_severity",
)

REDHAT_AGGREGATE = ScoringSystem(
    identifier="rhas",
    name="RedHat Aggregate severity",
    url="https://access.redhat.com/security/updates/classification/",
)

ARCHLINUX = ScoringSystem(
    identifier="avgs",
    name="Archlinux Vulnerability Group Severity",
    url="https://wiki.archlinux.org/index.php/Bug_reporting_guidelines#Severity",
)

CVSS31_QUALITY = ScoringSystem(
    identifier="cvssv3.1_qr",
    name="CVSSv3.1 Qualitative Severity Rating",
    url="https://www.first.org/cvss/specification-document#Qualitative-Severity-Rating-Scale",
    notes="A textual interpretation of severity. Has values like HIGH, MEDIUM etc",
)

GENERIC = ScoringSystem(
    identifier="generic_textual",
    name="Generic textual severity rating",
    url="",
    notes="Severity for generic scoring systems. Contains generic textual "
    "values like High, Low etc",
)

APACHE_HTTPD = ScoringSystem(
    identifier="apache_httpd",
    name="Apache Httpd Severity",
    url="https://httpd.apache.org/security/impact_levels.html",
)

SCORING_SYSTEMS = {
    "cvssv2": CVSSV2,
    "cvssv2_vector": CVSSV2_VECTOR,
    "cvssv3": CVSSV3,
    "cvssv3_vector": CVSSV3_VECTOR,
    "cvssv3.1": CVSSV31,
    "cvssv3.1_vector": CVSSV31_VECTOR,
    "rhbs": REDHAT_BUGZILLA,
    "rhas": REDHAT_AGGREGATE,
    "avgs": ARCHLINUX,
    "cvssv3.1_qr": CVSS31_QUALITY,
    "generic_textual": GENERIC,
    "apache_httpd": APACHE_HTTPD,
}
