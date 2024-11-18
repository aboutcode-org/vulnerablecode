#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.models import Exploit
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness
from vulnerabilities.risk import compute_vulnerability_risk_factors
from vulnerabilities.risk import get_exploitability_level
from vulnerabilities.risk import get_weighted_severity
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import EPSS
from vulnerabilities.severity_systems import GENERIC


@pytest.fixture
@pytest.mark.django_db
def vulnerability():
    vul = Vulnerability(vulnerability_id="VCID-Existing")
    vul.save()

    severity1 = VulnerabilitySeverity.objects.create(
        url="https://nvd.nist.gov/vuln/detail/CVE-xxxx-xxx1",
        scoring_system=CVSSV3.identifier,
        scoring_elements="CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:N/E:H/RL:O/RC:R/CR:H/MAC:H/MC:L",
        value="6.5",
    )

    severity2 = VulnerabilitySeverity.objects.create(
        url="https://nvd.nist.gov/vuln/detail/CVE-xxxx-xxx1",
        scoring_system=GENERIC.identifier,
        value="MODERATE",  # 6.9
    )
    vul.severities.add(severity1)
    vul.severities.add(severity2)

    weaknesses = Weakness.objects.create(cwe_id=119)
    vul.weaknesses.add(weaknesses)
    return vul


@pytest.fixture
@pytest.mark.django_db
def exploit():
    vul = Vulnerability(vulnerability_id="VCID-Exploit")
    vul.save()
    return Exploit.objects.create(vulnerability=vul, description="exploit description")


@pytest.fixture
@pytest.mark.django_db
def vulnerability_with_exploit_ref():
    vul = Vulnerability(vulnerability_id="VCID-Exploit-Ref")
    vul.save()

    reference_exploit = VulnerabilityReference.objects.create(
        reference_id="",
        reference_type=VulnerabilityReference.EXPLOIT,
        url="https://nvd.nist.gov/vuln/detail/CVE-xxxx-xxxx2",
    )

    VulnerabilityRelatedReference.objects.create(reference=reference_exploit, vulnerability=vul)
    return vul


@pytest.fixture
@pytest.mark.django_db
def high_epss_score():
    vul = Vulnerability(vulnerability_id="VCID-HIGH-EPSS")
    vul.save()

    severity = VulnerabilitySeverity.objects.create(
        url="https://nvd.nist.gov/vuln/detail/CVE-xxxx-xxx3",
        scoring_system=EPSS.identifier,
        value=".9",
    )
    vul.severities.add(severity)

    return vul.severities.all()


@pytest.fixture
@pytest.mark.django_db
def low_epss_score():
    vul = Vulnerability(vulnerability_id="VCID-LOW-EPSS")
    vul.save()

    severity = VulnerabilitySeverity.objects.create(
        url="https://nvd.nist.gov/vuln/detail/CVE-xxxx-xxx4",
        scoring_system=EPSS.identifier,
        value=".3",
    )
    vul.severities.add(severity)

    return vul.severities.all()


@pytest.mark.django_db
def test_exploitability_level(
    exploit, vulnerability_with_exploit_ref, high_epss_score, low_epss_score
):

    assert get_exploitability_level(exploit, None, None) == 2

    assert get_exploitability_level(None, None, high_epss_score) == 2

    assert get_exploitability_level(None, None, low_epss_score) == 0.5

    assert (
        get_exploitability_level(
            exploits=None,
            references=vulnerability_with_exploit_ref.references.all(),
            severities=vulnerability_with_exploit_ref.severities.all(),
        )
        == 1
    )

    assert get_exploitability_level(None, None, None) == 0.5


@pytest.mark.django_db
def test_get_weighted_severity(vulnerability):
    severities = vulnerability.severities.all()
    assert get_weighted_severity(severities) == 6.2

    severity2 = VulnerabilitySeverity.objects.create(
        url="https://security-tracker.debian.org/tracker/CVE-2019-13057",
        scoring_system=GENERIC.identifier,
        value="CRITICAL",
    )
    vulnerability.severities.add(severity2)

    new_severities = vulnerability.severities.all()
    assert get_weighted_severity(new_severities) == 7


@pytest.mark.django_db
def test_compute_vulnerability_risk_factors(vulnerability, exploit):
    severities = vulnerability.severities.all()
    references = vulnerability.references.all()

    assert compute_vulnerability_risk_factors(references, severities, exploit) == (
        6.2,
        2,
    )

    assert compute_vulnerability_risk_factors(references, severities, None) == (6.2, 0.5)

    assert compute_vulnerability_risk_factors(references, None, exploit) == (0, 2)

    assert compute_vulnerability_risk_factors(None, None, None) == (0, 0.5)


@pytest.mark.django_db
def test_get_vulnerability_risk_score(vulnerability):
    vulnerability.weighted_severity = 6.0
    vulnerability.exploitability = 2

    assert vulnerability.risk_score == 10.0  # max risk_score can be reached

    vulnerability.weighted_severity = 6
    vulnerability.exploitability = 0.5
    assert vulnerability.risk_score == 3.0

    vulnerability.weighted_severity = 5.6
    vulnerability.exploitability = 0.5
    assert vulnerability.risk_score == 2.8

    vulnerability.weighted_severity = None
    vulnerability.exploitability = 0.5
    assert vulnerability.risk_score is None

    vulnerability.weighted_severity = None
    vulnerability.exploitability = None
    assert vulnerability.risk_score is None
