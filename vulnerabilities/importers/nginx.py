#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from typing import Iterable
from typing import List
from typing import NamedTuple

import requests
from bs4 import BeautifulSoup
from django.db.models.query import QuerySet
from packageurl import PackageURL
from univers.version_range import NginxVersionRange
from univers.versions import NginxVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import GENERIC

logger = logging.getLogger(__name__)


class NginxImporter(Importer):

    url = "https://nginx.org/en/security_advisories.html"

    spdx_license_expression = "BSD-2-Clause"
    license_url = "https://nginx.org/LICENSE"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        text = self.fetch()
        yield from advisory_data_from_text(text)

    def fetch(self):
        return requests.get(self.url).content


def advisory_data_from_text(text):
    """
    Yield AdvisoryData from the ``text`` of the nginx security advisories HTML
    web page.
    """
    soup = BeautifulSoup(text, features="lxml")
    vuln_list = soup.select("li p")
    for vuln_info in vuln_list:
        ngnix_adv = parse_advisory_data_from_paragraph(vuln_info)
        yield to_advisory_data(ngnix_adv)


class NginxAdvisory(NamedTuple):
    aliases: list
    summary: str
    advisory_severity: str
    not_vulnerable: str
    vulnerable: str
    references: list

    def to_dict(self):
        return self._asdict()


def to_advisory_data(ngnx_adv: NginxAdvisory) -> AdvisoryData:
    """
    Return AdvisoryData from an NginxAdvisory tuple.
    """
    package_name = "nginx"
    package_type = "nginx"
    qualifiers = {}

    _, _, affected_version_range = ngnx_adv.vulnerable.partition(":")
    if "nginx/Windows" in affected_version_range:
        qualifiers["os"] = "windows"
        affected_version_range = affected_version_range.replace("nginx/Windows", "")

    purl = PackageURL(type=package_type, name=package_name, qualifiers=qualifiers)

    affected_version_range = NginxVersionRange.from_native(affected_version_range)

    affected_packages = []
    _, _, fixed_versions = ngnx_adv.not_vulnerable.partition(":")

    for fixed_version in fixed_versions.split(","):
        fixed_version = fixed_version.rstrip("+")

        # TODO: Mail nginx for this anomaly (create ticket on our side)
        if "none" in fixed_version:
            affected_packages.append(
                AffectedPackage(
                    package=purl,
                    affected_version_range=affected_version_range,
                )
            )
            break

        fixed_version = NginxVersion(fixed_version)
        affected_packages.append(
            AffectedPackage(
                package=purl,
                affected_version_range=affected_version_range,
                fixed_version=fixed_version,
            )
        )

    return AdvisoryData(
        aliases=ngnx_adv.aliases,
        summary=ngnx_adv.summary,
        affected_packages=affected_packages,
        references=ngnx_adv.references,
    )


def parse_advisory_data_from_paragraph(vuln_info):
    """
    Return an NginxAdvisory from a ``vuln_info`` bs4 paragraph.

    An advisory paragraph, without html markup, looks like this:

        1-byte memory overwrite in resolver
        Severity: medium
        Advisory
        CVE-2021-23017
        Not vulnerable: 1.21.0+, 1.20.1+
        Vulnerable: 0.6.18-1.20.0
        The patch  pgp

    """
    aliases = []
    summary = None
    advisory_severity = None
    not_vulnerable = None
    vulnerable = None
    references = []
    is_first = True

    # we iterate on the children to accumulate values in variables
    # FIXME: using an explicit xpath-like query could be simpler
    for child in vuln_info.children:
        if is_first:
            summary = child
            is_first = False
            continue

        text = child.text.strip()
        text_low = text.lower()

        if text.startswith(
            (
                "CVE-",
                "CORE-",
                "VU#",
            )
        ):
            aliases.append(text)
            if text.startswith("CVE-"):

                # always keep the CVE as a reference too
                link = f"https://nvd.nist.gov/vuln/detail/{text}"
                reference = Reference(reference_id=text, url=link)
                references.append(reference)

        elif "severity" in text_low:
            advisory_severity = build_severity(severity=text)

        elif "not vulnerable" in text_low:
            not_vulnerable = text

        elif "vulnerable" in text_low:
            vulnerable = text

        elif hasattr(child, "attrs"):
            link = child.attrs.get("href")
            if link:
                if "cve.mitre.org" in link:
                    references.append(Reference(reference_id=text, url=link))
                elif "mailman.nginx.org" in link:
                    if advisory_severity:
                        severities = [advisory_severity]
                    else:
                        severities = []
                    references.append(Reference(url=link, severities=severities))
                else:
                    link = requests.compat.urljoin("https://nginx.org", link)
                    references.append(Reference(url=link))

    return NginxAdvisory(
        aliases=aliases,
        summary=summary,
        advisory_severity=advisory_severity,
        not_vulnerable=not_vulnerable,
        vulnerable=vulnerable,
        references=references,
    )


def build_severity(severity):
    """
    Return a VulnerabilitySeverity built from a ``severity`` string, or None.

    For example::
    >>> severity = "Severity: medium"
    >>> expected = VulnerabilitySeverity(system=GENERIC, value="medium")
    >>> assert build_severity(severity) == expected
    """
    if severity.startswith("Severity:"):
        _, _, severity = severity.partition("Severity:")

    severity = severity.strip()
    if severity:
        return VulnerabilitySeverity(system=GENERIC, value=severity)
