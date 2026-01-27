# redhat.py (updated snippet with helper function)

from vulnerabilities.importers.utils import filter_purls
import logging
import re
from typing import Dict, Iterable, List

import requests
from packageurl import PackageURL
from univers.version_range import RpmVersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData, AffectedPackage, Importer, Reference, VulnerabilitySeverity
from vulnerabilities.rpm_utils import rpm_to_purl
from vulnerabilities.utils import get_cwe_id, get_item, requests_with_5xx_retry

logger = logging.getLogger(__name__)

requests_session = requests_with_5xx_retry(max_retries=5, backoff_factor=1)


def fetch_cves() -> Iterable[List[Dict]]:
    page_no = 1
    while True:
        current_url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?per_page=1000&page={page_no}"  # nopep8
        try:
            response = requests_session.get(current_url)
            if response.status_code != requests.codes.ok:
                logger.error(f"Failed to fetch RedHat CVE results from {current_url}")
                break
            cve_data = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch RedHat CVE results from {current_url} {e}")
            break
        if not cve_data:
            break
        page_no += 1
        yield cve_data


def get_data_from_url(url):
    try:
        return requests_session.get(url).json()
    except Exception as e:
        logger.error(f"Failed to fetch results from {url} {e!r}")
        return {}


class RedhatImporter(Importer):
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://access.redhat.com/documentation/en-us/red_hat_security_data_api/1.0/html/red_hat_security_data_api/legal-notice"
    importer_name = "RedHat Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        for redhat_cves in fetch_cves():
            for redhat_cve in redhat_cves:
                yield to_advisory(redhat_cve)


def to_advisory(advisory_data):
    affected_packages: List[AffectedPackage] = []
    for rpm in advisory_data.get("affected_packages") or []:
        purl = rpm_to_purl(rpm_string=rpm, namespace="redhat")

        # Replace duplicate logic with helper
        filtered_purls = filter_purls([purl])

        for p in filtered_purls:
            try:
                affected_version_range = RpmVersionRange.from_versions(sequence=[p.version])
                affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(
                            type=p.type,
                            name=p.name,
                            namespace=p.namespace,
                            qualifiers=p.qualifiers,
                            subpath=p.subpath,
                        ),
                        affected_version_range=affected_version_range,
                        fixed_version=None,
                    )
                )
            except Exception as e:
                logger.error(f"Failed to parse version range {p.version} for {p} {e}")

    references = []
    bugzilla = advisory_data.get("bugzilla")
    if bugzilla:
        url = f"https://bugzilla.redhat.com/show_bug.cgi?id={bugzilla}"
        references.append(Reference(url=url, reference_id=bugzilla))

    for rh_adv in advisory_data.get("advisories") or []:
        if not isinstance(rh_adv, str):
            logger.error(f"Invalid advisory type {rh_adv}")
            continue

        if "RHSA" in rh_adv.upper():
            references.append(
                Reference(
                    url=f"https://access.redhat.com/errata/{rh_adv}",
                    reference_id=rh_adv,
                )
            )
        else:
            references.append(Reference(severities=[], url=url, reference_id=rh_adv))

    redhat_scores = []
    cvssv3_score = advisory_data.get("cvss3_score")
    cvssv3_vector = advisory_data.get("cvss3_scoring_vector", "")
    if cvssv3_score:
        redhat_scores.append(
            VulnerabilitySeverity(
                system=severity_systems.CVSSV3,
                value=cvssv3_score,
                scoring_elements=cvssv3_vector,
            )
        )

    cwe_list = []
    cwe_string = advisory_data.get("CWE")
    if cwe_string:
        cwe_list = list(map(get_cwe_id, re.findall("CWE-[0-9]+", cwe_string)))

    aliases = []
    alias = advisory_data.get("CVE")
    if alias:
        aliases.append(alias)

    resource_url = advisory_data.get("resource_url")
    if resource_url:
        references.append(Reference(severities=redhat_scores, url=resource_url))

    return AdvisoryData(
        aliases=aliases,
        summary=advisory_data.get("bugzilla_description") or "",
        affected_packages=affected_packages,
        references=references,
        weaknesses=cwe_list,
        url=resource_url if resource_url else "https://access.redhat.com/hydra/rest/securitydata/cve.json",
    )
