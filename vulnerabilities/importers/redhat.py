#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from typing import Dict
from typing import Iterable
from typing import List

import requests
from packageurl import PackageURL
from univers.version_range import RpmVersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.rpm_utils import rpm_to_purl
from vulnerabilities.utils import get_item
from vulnerabilities.utils import requests_with_5xx_retry

logger = logging.getLogger(__name__)

# FIXME: we should use a centralized retry
requests_session = requests_with_5xx_retry(max_retries=5, backoff_factor=1)


def fetch_cves() -> Iterable[List[Dict]]:
    page_no = 1
    cve_data = None
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

    def advisory_data(self) -> Iterable[AdvisoryData]:
        for redhat_cves in fetch_cves():
            for redhat_cve in redhat_cves:
                yield to_advisory(redhat_cve)


def to_advisory(advisory_data):
    affected_packages: List[AffectedPackage] = []
    for rpm in advisory_data.get("affected_packages") or []:
        purl = rpm_to_purl(rpm_string=rpm, namespace="redhat")
        if purl:
            try:
                affected_version_range = RpmVersionRange.from_versions(sequence=[purl.version])
                affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(
                            type=purl.type,
                            name=purl.name,
                            namespace=purl.namespace,
                            qualifiers=purl.qualifiers,
                            subpath=purl.subpath,
                        ),
                        affected_version_range=affected_version_range,
                        fixed_version=None,
                    )
                )
            except Exception as e:
                logger.error(f"Failed to parse version range {purl.version} for {purl} {e}")

    references = []
    bugzilla = advisory_data.get("bugzilla")
    if bugzilla:
        url = "https://bugzilla.redhat.com/show_bug.cgi?id={}".format(bugzilla)
        bugzilla_url = f"https://bugzilla.redhat.com/rest/bug/{bugzilla}"
        bugzilla_data = get_data_from_url(bugzilla_url)
        bugs = bugzilla_data.get("bugs") or []
        if bugs:
            # why [0] only here?
            severity = bugs[0].get("severity")
            if severity:
                bugzilla_severity = VulnerabilitySeverity(
                    system=severity_systems.REDHAT_BUGZILLA,
                    value=severity,
                )
                references.append(
                    Reference(
                        severities=[bugzilla_severity],
                        url=url,
                        reference_id=bugzilla,
                    )
                )

    for rh_adv in advisory_data.get("advisories") or []:
        # RH provides 3 types of advisories RHSA, RHBA, RHEA. Only RHSA's contain severity score.
        # See https://access.redhat.com/articles/2130961 for more details.

        if not isinstance(rh_adv, str):
            logger.error(f"Invalid advisory type {rh_adv}")
            continue

        if "RHSA" in rh_adv.upper():
            rhsa_url = f"https://access.redhat.com/hydra/rest/securitydata/cvrf/{rh_adv}.json"
            rhsa_data = get_data_from_url(rhsa_url)
            if not rhsa_data:
                continue
            rhsa_aggregate_severities = []
            if rhsa_data.get("cvrfdoc"):
                # not all RHSA errata have a corresponding CVRF document
                value = get_item(rhsa_data, "cvrfdoc", "aggregate_severity")
                if value:
                    rhsa_aggregate_severities.append(
                        VulnerabilitySeverity(
                            system=severity_systems.REDHAT_AGGREGATE,
                            value=value,
                        )
                    )

            references.append(
                Reference(
                    severities=rhsa_aggregate_severities,
                    url="https://access.redhat.com/errata/{}".format(rh_adv),
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
    )
