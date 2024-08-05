#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
from typing import Dict
from typing import Iterable
from typing import List

import dateparser
import requests
from cwe2.database import Database
from packageurl import PackageURL
from univers.version_range import RpmVersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.rpm_utils import rpm_to_purl
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item
from vulnerabilities.utils import requests_with_5xx_retry

logger = logging.getLogger(__name__)

# FIXME: we should use a centralized retry
requests_session = requests_with_5xx_retry(max_retries=5, backoff_factor=1)


def fetch_cves() -> Iterable[List[Dict]]:
    page_no = 0
    cve_data_list = []
    while True:
        current_url = f"https://errata.rockylinux.org/api/v2/advisories?filters.product=&filters.fetchRelated=true&page={page_no}&limit=100"
        try:
            response = requests_session.get(current_url)
            if response.status_code != requests.codes.ok:
                logger.error(f"Failed to fetch RedHat CVE results from {current_url}")
                break
            cve_data = response.json().get("advisories") or []
            cve_data_list.extend(cve_data)
        except Exception as e:
            logger.error(f"Failed to fetch rockylinux CVE results from {current_url} {e}")
            break
        if not cve_data:
            break
        page_no += 1
    return cve_data_list


class RockyLinuxImporter(Importer):
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://access.redhat.com/security/data"
    importer_name = "Rocky Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:

        for rockylinux_cve in fetch_cves():
            yield to_advisory(rockylinux_cve)


def to_advisory(advisory_data):
    aliases = advisory_data.get("name") or ""
    date_published = dateparser.parse(advisory_data.get("publishedAt", ""))

    summary = advisory_data.get("description") or ""
    affected_products = advisory_data.get("affectedProducts") or []
    affected_packages = []
    for products in affected_products:
        packages = advisory_data["rpms"][products]["nvras"]
        affected_packages.extend(packages)
    processed_affected_packages: List[AffectedPackage] = []
    for rpm in affected_packages:
        purl = rpm_to_purl(rpm_string=rpm.rsplit(".rpm", 1)[0] or "", namespace="rocky-linux")
        if purl:
            try:
                affected_version_range = RpmVersionRange.from_versions(sequence=[purl.version])
                processed_affected_packages.append(
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

    references = [
        Reference(
            severities=[], url=fix.get("sourceLink") or "", reference_id=fix.get("ticket") or ""
        )
        for fix in advisory_data["fixes"]
    ]

    for ref in advisory_data.get("cves") or []:

        name = ref.get("name", "")
        if not isinstance(name, str):
            logger.error(f"Invalid advisory type {name}")
            continue

        if "CVE" in name.upper():
            severity_vector_pattern = r"CVSS:3\.1/([A-Z:/]+)"
            severities = VulnerabilitySeverity(
                system=severity_systems.CVSSV31,
                value=ref.get("cvss3BaseScore", ""),
                scoring_elements=re.findall(
                    severity_vector_pattern, ref.get("cvss3ScoringVector", "")
                ),
            )
            references.append(
                Reference(
                    severities=[severities],
                    url=ref.get("sourceLink", ""),
                    reference_id=name,
                )
            )

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        affected_packages=processed_affected_packages,
        references=references,
        date_published=date_published,
        weaknesses=get_cwes_from_rockylinux_advisory(advisory_data),
        url=f"https://errata.rockylinux.org/{aliases}",
    )


def get_cwes_from_rockylinux_advisory(advisory_data) -> [int]:
    """
    Extract CWE IDs from advisory data and validate them against a database.

    :param advisory_data: Dictionary containing CVE information.
    :return: List of valid CWE IDs.

        >>> advisory_data = {"cves": [
        ...     {
        ...         "name": "CVE-2022-24999",
        ...         "sourceBy": "MITRE",
        ...         "sourceLink": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-24999",
        ...         "cvss3ScoringVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        ...         "cvss3BaseScore": "7.5",
        ...         "cwe": "CWE-1321"
        ...     },
        ...     {
        ...         "name": "CVE-2022-3517",
        ...         "sourceBy": "MITRE",
        ...         "sourceLink": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3517",
        ...         "cvss3ScoringVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        ...         "cvss3BaseScore": "7.5",
        ...         "cwe": "CWE-400"
        ...     },
        ...     {
        ...         "name": "CVE-2022-43548",
        ...         "sourceBy": "MITRE",
        ...         "sourceLink": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-43548",
        ...         "cvss3ScoringVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        ...         "cvss3BaseScore": "7.5",
        ...         "cwe": "CWE-350"
        ...     }
        ... ]}
        >>> get_cwes_from_rockylinux_advisory(advisory_data)
        [1321, 400, 350]
        >>> get_cwes_from_rockylinux_advisory({"cves": [{"name": "CVE-1234-1234","cwe": "None"}]})
        []
    """

    cwe_ids = []
    for cve in advisory_data.get("cves", []):
        cwe_pattern = r"CWE-\d+"
        cwe_id_list = re.findall(cwe_pattern, cve.get("cwe", ""))
        cwe_ids.extend(cwe_id_list)
    weaknesses = []
    db = Database()
    for cwe_string in cwe_ids:
        if cwe_string:
            cwe_id = get_cwe_id(cwe_string)
            try:
                db.get(cwe_id)
                weaknesses.append(cwe_id)
            except Exception:
                logger.error("Invalid CWE id")
    return weaknesses
