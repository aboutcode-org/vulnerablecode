#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from urllib.parse import urlparse

from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.severity_systems import EPSS
from vulnerabilities.weight_config import WEIGHT_CONFIG

DEFAULT_WEIGHT = 5


def get_weighted_severity(severities):
    """
    Weighted Severity is the maximum value obtained when each Severity is multiplied
    by its associated Weight/10.
    Example of Weighted Severity: max(7*(10/10), 8*(3/10), 6*(8/10)) = 7
    """
    if not severities:
        return 0

    score_map = {
        "low": 3,
        "moderate": 6.9,
        "medium": 6.9,
        "high": 8.9,
        "important": 8.9,
        "critical": 10.0,
        "urgent": 10.0,
    }

    score_list = []
    for severity in severities:
        parsed_url = urlparse(severity.url)
        severity_source = parsed_url.netloc.replace("www.", "", 1)
        weight = WEIGHT_CONFIG.get(severity_source, DEFAULT_WEIGHT)
        max_weight = float(weight) / 10
        vul_score = severity.value
        try:
            vul_score = float(vul_score)
            vul_score_value = vul_score * max_weight
        except ValueError:
            vul_score = vul_score.lower()
            vul_score_value = score_map.get(vul_score, 0) * max_weight

        score_list.append(vul_score_value)

    max_score = max(score_list) if score_list else 0
    return round(max_score, 1)


def get_exploitability_level(exploits, references, severities):
    """
    Exploitability refers to the potential or
    probability of a software package vulnerability being exploited by
    malicious actors to compromise systems, applications, or networks.
    It is determined automatically by discovery of exploits.
    """
    # no exploit known ( default .5)
    exploit_level = 0.5

    if exploits:
        # Automatable Exploit with PoC script published OR known exploits (KEV) in the wild OR known ransomware
        exploit_level = 2

    elif severities:
        # high EPSS.
        for severity in severities:
            if severity.scoring_system == EPSS.identifier and float(severity.value) > 0.8:
                exploit_level = 2
                break

    elif references:
        # PoC/Exploit script published
        for reference in references:
            if reference.reference_type == VulnerabilityReference.EXPLOIT:
                exploit_level = 1
                break

    return exploit_level


def compute_vulnerability_risk_factors(references, severities, exploits):
    """
    Risk may be expressed as a number ranging from 0 to 10.
    Risk is calculated from weighted severity and exploitability values.
    It is the maximum value of (the weighted severity multiplied by its exploitability) or 10

    Risk = min(weighted severity * exploitability, 10)
    """
    weighted_severity = get_weighted_severity(severities)
    exploitability = get_exploitability_level(exploits, references, severities)
    return weighted_severity, exploitability


def compute_package_risk(package):
    """
    Calculate the risk for a package by iterating over all vulnerabilities that affects this package
    and determining the associated risk.
    """
    result = []
    for relation in package.affectedbypackagerelatedvulnerability_set.all():
        if risk := relation.vulnerability.risk_score:
            result.append(float(risk))

    if not result:
        return

    return round(max(result), 1)
