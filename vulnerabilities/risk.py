from pathlib import Path
from urllib.parse import urlparse

from vulnerabilities.models import AffectedByPackageRelatedVulnerability
from vulnerabilities.models import Exploit
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.severity_systems import EPSS
from vulnerabilities.utils import load_json

DEFAULT_WEIGHT = 5
WEIGHT_CONFIG_PATH = Path(__file__).parent.parent / "weight_config.json"
WEIGHT_CONFIG = load_json(WEIGHT_CONFIG_PATH)


def get_weighted_severity(severities):
    """
    Weighted Severity is the maximum value obtained when each Severity is multiplied
    by its associated Weight/10.
    Example of Weighted Severity: max(7*(10/10), 8*(3/10), 6*(8/10)) = 7
    """

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
        parsed_url = urlparse(severity.reference.url)
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
    return max(score_list) if score_list else 0


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
        epss = severities.filter(
            scoring_system=EPSS.identifier,
        )
        epss = any(float(epss.value) > 0.8 for epss in epss)
        if epss:
            exploit_level = 2

    elif references:
        # PoC/Exploit script published
        ref_exploits = references.filter(
            reference_type=VulnerabilityReference.EXPLOIT,
        )
        if ref_exploits:
            exploit_level = 1

    return exploit_level


def compute_vulnerability_risk(vulnerability: Vulnerability):
    """
    Risk may be expressed as a number ranging from 0 to 10.
    Risk is calculated from weighted severity and exploitability values.
    It is the maximum value of (the weighted severity multiplied by its exploitability) or 10

    Risk = min(weighted severity * exploitability, 10)
    """
    references = vulnerability.references
    severities = vulnerability.severities.select_related("reference")
    exploits = Exploit.objects.filter(vulnerability=vulnerability)
    if references.exists() or severities.exists() or exploits.exists():
        weighted_severity = get_weighted_severity(severities)
        exploitability = get_exploitability_level(exploits, references, severities)
        return min(weighted_severity * exploitability, 10)


def compute_package_risk(package: Package):
    """
    Calculate the risk for a package by iterating over all vulnerabilities that affects this package
    and determining the associated risk.
    """

    result = []
    for pkg_related_vul in AffectedByPackageRelatedVulnerability.objects.filter(
        package=package
    ).prefetch_related("vulnerability"):
        if risk := compute_vulnerability_risk(pkg_related_vul.vulnerability):
            result.append(risk)

    if not result:
        return

    return f"{max(result):.2f}"