import pytest
from cvss.exceptions import CVSS2MalformedError
from cvss.exceptions import CVSS3MalformedError

from vulnerabilities.severity_systems import CVSSV2
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.templatetags.show_cvss import cvss_printer


def test_get_cvss2_vector_values():
    assert (
        CVSSV2.get("AV:N/AC:L/Au:N/C:P/I:N/A:N  ")
        == CVSSV2.get("AV:N/AC:L/Au:N/C:P/I:N/A:N")
        == {
            "accessComplexity": "LOW",
            "accessVector": "NETWORK",
            "authentication": "NONE",
            "availabilityImpact": "NONE",
            "availabilityRequirement": "NOT_DEFINED",
            "baseScore": 5.0,
            "collateralDamagePotential": "NOT_DEFINED",
            "confidentialityImpact": "PARTIAL",
            "confidentialityRequirement": "NOT_DEFINED",
            "environmentalScore": 0.0,
            "exploitability": "NOT_DEFINED",
            "integrityImpact": "NONE",
            "integrityRequirement": "NOT_DEFINED",
            "remediationLevel": "NOT_DEFINED",
            "reportConfidence": "NOT_DEFINED",
            "targetDistribution": "NOT_DEFINED",
            "temporalScore": 0.0,
            "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
            "version": "2.0",
        }
    )

    with pytest.raises(CVSS2MalformedError):
        CVSSV2.get("")

    with pytest.raises(CVSS2MalformedError):
        CVSSV2.get("AV:N/AffgL/Au:N/C:P/I:N/A:N  ")


def test_get_cvss3_vector_values():
    assert (
        CVSSV3.get("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H  ")
        == CVSSV3.get("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H")
        == {
            "attackComplexity": "LOW",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "availabilityRequirement": "NOT_DEFINED",
            "baseScore": 9.1,
            "baseSeverity": "CRITICAL",
            "confidentialityImpact": "HIGH",
            "confidentialityRequirement": "NOT_DEFINED",
            "environmentalScore": 9.1,
            "environmentalSeverity": "CRITICAL",
            "exploitCodeMaturity": "NOT_DEFINED",
            "integrityImpact": "HIGH",
            "integrityRequirement": "NOT_DEFINED",
            "modifiedAttackComplexity": "LOW",
            "modifiedAttackVector": "NETWORK",
            "modifiedAvailabilityImpact": "HIGH",
            "modifiedConfidentialityImpact": "HIGH",
            "modifiedIntegrityImpact": "HIGH",
            "modifiedPrivilegesRequired": "HIGH",
            "modifiedScope": "CHANGED",
            "modifiedUserInteraction": "NONE",
            "privilegesRequired": "HIGH",
            "remediationLevel": "NOT_DEFINED",
            "reportConfidence": "NOT_DEFINED",
            "scope": "CHANGED",
            "temporalScore": 9.1,
            "temporalSeverity": "CRITICAL",
            "userInteraction": "NONE",
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
            "version": "3.1",
        }
    )

    with pytest.raises(CVSS3MalformedError):
        CVSSV3.get("CVSS:3.7/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H  ")

    with pytest.raises(CVSS3MalformedError):
        CVSSV3.get("")


def test_blank_cvss_printer():
    result = cvss_printer("", "")
    assert result == "<p class='has-text-black-bis mb-2'></p>"


def test_cvss_printer():
    result = cvss_printer("HIGH", "high,medium,low")
    assert result == (
        "<p class='has-text-black-bis mb-2'>high</p>"
        "<p class='has-text-grey mb-2'>medium</p>"
        "<p class='has-text-grey mb-2'>low</p>"
    )
