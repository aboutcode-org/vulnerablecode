#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import timezone
from typing import Iterable
from urllib.parse import urljoin

import defusedxml.ElementTree as DET
import requests
from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_range import OpensslVersionRange
from univers.versions import OpensslVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)


class OpensslImporter(Importer):
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/openssl/openssl/blob/master/LICENSE.txt"
    url = "https://www.openssl.org/news/vulnerabilities.xml"

    def fetch(self):
        response = requests.get(url=self.url)
        if not response.status_code == 200:
            logger.error(f"Error while fetching {self.url}: {response.status_code}")
            return
        return response.content

    def advisory_data(self) -> Iterable[AdvisoryData]:
        xml_response = self.fetch()
        return parse_vulnerabilities(xml_response)


def parse_vulnerabilities(xml_response) -> Iterable[AdvisoryData]:
    root = DET.fromstring(xml_response)
    for xml_issue in root:
        if xml_issue.tag == "issue":
            advisory = to_advisory_data(xml_issue)
            if advisory:
                yield advisory


def to_advisory_data(xml_issue) -> AdvisoryData:
    """
    Return AdvisoryData from given xml_issue
    """

    purl = PackageURL(type="openssl", name="openssl")
    cve = advisory_url = severity = summary = None
    safe_pkg_versions = {}
    vuln_pkg_versions_by_base_version = {}
    aliases = []
    references = []
    affected_packages = []
    date_published = xml_issue.attrib["public"].strip()

    for info in xml_issue:
        if info.tag == "impact":
            severity = VulnerabilitySeverity(
                system=SCORING_SYSTEMS["generic_textual"], value=info.attrib["severity"]
            )

        elif info.tag == "advisory":
            advisory_url = info.attrib["url"]
            if not advisory_url.startswith("https://web.archive.org"):
                advisory_url = urljoin("https://www.openssl.org", advisory_url)

        elif info.tag == "cve":
            cve = info.attrib.get("name")
            # use made up alias to compensate for case when advisory doesn't have CVE-ID
            madeup_alias = f"VC-OPENSSL-{date_published}"
            if cve:
                cve = f"CVE-{cve}"
                madeup_alias = f"{madeup_alias}-{cve}"
                aliases.append(cve)
                references.append(
                    Reference(reference_id=cve, url=f"https://nvd.nist.gov/vuln/detail/{cve}")
                )
            aliases.append(madeup_alias)

        elif info.tag == "affects":
            affected_base = info.attrib["base"]
            affected_version = info.attrib["version"]
            if affected_base.startswith("fips"):
                logger.error(
                    f"{affected_base!r} is a OpenSSL-FIPS Object Module and isn't supported by OpensslImporter. Use a different importer."
                )
                return
            if affected_base in vuln_pkg_versions_by_base_version:
                vuln_pkg_versions_by_base_version[affected_base].append(affected_version)
            else:
                vuln_pkg_versions_by_base_version[affected_base] = [affected_version]

        elif info.tag == "fixed":
            fixed_base = info.attrib["base"]
            fixed_version = info.attrib["version"]
            safe_pkg_versions[fixed_base] = fixed_version
            for commit in info:
                commit_hash = commit.attrib["hash"]
                references.append(
                    Reference(
                        url=urljoin("https://github.com/openssl/openssl/commit/", commit_hash)
                    )
                )

        elif info.tag == "description":
            summary = " ".join(info.text.split())

        elif info.tag in ("reported", "problemtype", "title"):
            # as of now, these info isn't useful for AdvisoryData
            # for more see: https://github.com/nexB/vulnerablecode/issues/688
            continue
        else:
            logger.error(
                f"{info.tag!r} is a newly introduced tag. Modify the importer to make use of this new info."
            )

    for base_version, affected_versions in vuln_pkg_versions_by_base_version.items():
        affected_version_range = OpensslVersionRange.from_versions(affected_versions)
        fixed_version = None
        if base_version in safe_pkg_versions:
            fixed_version = OpensslVersion(safe_pkg_versions[base_version])
        affected_package = AffectedPackage(
            package=purl,
            affected_version_range=affected_version_range,
            fixed_version=fixed_version,
        )
        affected_packages.append(affected_package)

    if severity and advisory_url:
        references.append(Reference(url=advisory_url, severities=[severity]))
    elif advisory_url:
        references.append(Reference(url=advisory_url))

    parsed_date_published = dateparser.parse(date_published, yearfirst=True).replace(
        tzinfo=timezone.utc
    )

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        affected_packages=affected_packages,
        references=references,
        date_published=parsed_date_published,
    )
