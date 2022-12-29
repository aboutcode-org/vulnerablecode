#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses

from cvss import CVSS2
from cvss import CVSS3

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

    def compute(self, scoring_elements: str) -> str:
        """
        Return a normalized numeric score as a string for this scoring system
        given a ``scoring_elements`` string value.
        """
        return NotImplementedError


@dataclasses.dataclass(order=True)
class Cvssv2ScoringSystem(ScoringSystem):
    def compute(self, scoring_elements: str) -> str:
        """
        Return a CVSSv2 base score.

        >>> CVSSV2.compute("AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M")
        '5.0'
        """
        return str(CVSS2(vector=scoring_elements).base_score)


CVSSV2 = Cvssv2ScoringSystem(
    identifier="cvssv2",
    name="CVSSv2 Base Score",
    url="https://www.first.org/cvss/v2/",
    notes="CVSSv2 base score and vector",
)


@dataclasses.dataclass(order=True)
class Cvssv3ScoringSystem(ScoringSystem):
    def compute(self, scoring_elements: str) -> str:
        """
        Return a CVSSv3 or CVSSv3.1 base score.

        >>> CVSSV3.compute("CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X")
        '6.5'
        >>> CVSSV31.compute("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H")
        '8.6'
        """
        return str(CVSS3(vector=scoring_elements).base_score)


CVSSV3 = Cvssv3ScoringSystem(
    identifier="cvssv3",
    name="CVSSv3 Base Score",
    url="https://www.first.org/cvss/v3-0/",
    notes="CVSSv3 base score and vector",
)

CVSSV31 = Cvssv3ScoringSystem(
    identifier="cvssv3.1",
    name="CVSSv3.1 Base Score",
    url="https://www.first.org/cvss/v3-1/",
    notes="CVSSv3.1 base score and vector",
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
    identifier="archlinux",
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
APACHE_HTTPD.choices = [
    "Critical",
    "Important",
    "Moderate",
    "Low",
]

# This is essentially identical to apache_http except for the addition of the "High" score,
# which seems to be used interchangeably for "Important".
APACHE_TOMCAT = ScoringSystem(
    identifier="apache_tomcat",
    name="Apache Tomcat Severity",
    url="https://tomcat.apache.org/security-impact.html",
)
APACHE_TOMCAT.choices = [
    "Critical",
    "High",
    "Important",
    "Moderate",
    "Low",
]

SCORING_SYSTEMS = {
    system.identifier: system
    for system in (
        CVSSV2,
        CVSSV3,
        CVSSV31,
        REDHAT_BUGZILLA,
        REDHAT_AGGREGATE,
        ARCHLINUX,
        CVSS31_QUALITY,
        GENERIC,
        APACHE_HTTPD,
        APACHE_TOMCAT,
    )
}
