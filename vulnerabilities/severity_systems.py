#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses
from decimal import Decimal

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

    def as_score(self, value) -> Decimal:
        """
        Return a normalized numeric score for this scoring system  given a raw
        value. For instance this can be used to convert a CVSS vector to a base
        score.

        >>> SCORING_SYSTEMS["cvssv2_vector"].as_score("AV:L/AC:L/Au:M/C:N/I:P/A:C/E:U/RL:W/RC:ND/CDP:L/TD:H/CR:ND/IR:ND/AR:M")
        Decimal('5.0')
        >>> SCORING_SYSTEMS["cvssv3_vector"].as_score('CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X')
        Decimal('6.5')
        >>> SCORING_SYSTEMS["cvssv3.1_vector"].as_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H")
        Decimal('8.6')
        """

        if self.identifier == "cvssv2_vector":
            c = CVSS2(value)
            return c.base_score
        elif self.identifier in ["cvssv3_vector", "cvssv3.1_vector"]:
            c = CVSS3(value)
            return c.base_score
        else:
            raise NotImplementedError("Can't compute a score")


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

SCORING_SYSTEMS = {
    system.identifier: system
    for system in (
        CVSSV2,
        CVSSV2_VECTOR,
        CVSSV3,
        CVSSV3_VECTOR,
        CVSSV31,
        CVSSV31_VECTOR,
        REDHAT_BUGZILLA,
        REDHAT_AGGREGATE,
        ARCHLINUX,
        CVSS31_QUALITY,
        GENERIC,
        APACHE_HTTPD,
    )
}
