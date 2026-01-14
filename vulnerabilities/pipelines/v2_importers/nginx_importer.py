#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from typing import NamedTuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_constraint import validate_comparators
from univers.version_range import NginxVersionRange
from univers.versions import InvalidVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importer import logger
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC


class NginxImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect Nginx security advisories."""

    pipeline_id = "nginx_importer_v2"

    spdx_license_expression = "BSD-2-Clause"
    license_url = "https://nginx.org/LICENSE"
    url = "https://nginx.org/en/security_advisories.html"
    importer_name = "Nginx Importer"

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )

    def fetch(self):
        self.log(f"Fetch `{self.url}`")
        self.advisory_data = requests.get(self.url).text

    def advisories_count(self):
        return self.advisory_data.count("<li><p>")

    def collect_advisories(self):
        """
        Yield AdvisoryData from nginx security advisories HTML
        web page.
        """
        soup = BeautifulSoup(self.advisory_data, features="lxml")
        vulnerability_list = soup.select("li p")
        for vulnerability_info in vulnerability_list:
            ngnix_advisory = parse_advisory_data_from_paragraph(vulnerability_info)
            yield to_advisory_data(ngnix_advisory)


class NginxAdvisory(NamedTuple):
    advisory_id: str
    aliases: list
    summary: str
    severities: list
    patches: list
    not_vulnerable: str
    vulnerable: str
    references: list

    def to_dict(self):
        return self._asdict()


def to_advisory_data(nginx_adv: NginxAdvisory) -> AdvisoryData:
    """
    Return AdvisoryData from an NginxAdvisory tuple.
    """
    qualifiers = {}

    purl = PackageURL(type="nginx", name="nginx", qualifiers=qualifiers)

    _, _, affected_versions = nginx_adv.vulnerable.partition(":")
    affected_versions = affected_versions.strip()

    if "nginx/Windows" in affected_versions:
        qualifiers["os"] = "windows"
        affected_versions = affected_versions.replace("nginx/Windows", "")

    _, _, fixed_versions = nginx_adv.not_vulnerable.partition(":")
    fixed_versions = fixed_versions.strip()

    if "nginx/Windows" in fixed_versions:
        qualifiers["os"] = "windows"
        fixed_versions = fixed_versions.replace("nginx/Windows", "")

    fixed_version_range = None
    try:
        fixed_version_range = NginxVersionRange.from_native(fixed_versions)
    except InvalidVersion as e:
        logger.error(f"InvalidVersionRange fixed_version_range: {fixed_versions} - error: {e}")

    affected_version_range = None
    try:
        affected_version_range = NginxVersionRange.from_native(affected_versions)
    except InvalidVersion as e:
        logger.error(
            f"InvalidVersionRange affected_version_range: {affected_versions} - error: {e}"
        )

    affected_packages = []
    if purl and affected_version_range or fixed_version_range:
        try:
            if affected_version_range:
                validate_comparators(affected_version_range.constraints)
        except ValueError as e:
            affected_version_range = None
            logger.error(
                f"Invalid version_range affected_version_range:{affected_version_range} - error: {e}"
            )

        try:
            if fixed_version_range:
                fixed_version_constraints = VersionConstraint.simplify(
                    fixed_version_range.constraints
                )
                fixed_version_range = NginxVersionRange(constraints=fixed_version_constraints)
                validate_comparators(fixed_version_range.constraints)
        except ValueError as e:
            fixed_version_range = None
            logger.error(
                f"Invalid version_range fixed_version_range:{fixed_version_range} - error: {e}"
            )

        affected_packages.append(
            AffectedPackageV2(
                package=purl,
                affected_version_range=affected_version_range,
                fixed_version_range=fixed_version_range,
            )
        )

    return AdvisoryData(
        advisory_id=nginx_adv.advisory_id,
        aliases=nginx_adv.aliases,
        summary=nginx_adv.summary,
        affected_packages=affected_packages,
        references_v2=nginx_adv.references,
        patches=nginx_adv.patches,
        url="https://nginx.org/en/security_advisories.html",
    )


def parse_advisory_data_from_paragraph(vulnerability_info):
    """
    Return an NginxAdvisory from a ``vulnerability_info`` bs4 paragraph.

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
    severities = []
    patches = []
    not_vulnerable = None
    vulnerable = None
    references = []
    is_first = True

    # we iterate on the children to accumulate values in variables
    # FIXME: using an explicit xpath-like query could be simpler
    for child in vulnerability_info.children:
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
                reference = ReferenceV2(reference_id=text, url=link)
                references.append(reference)

        elif "severity" in text_low:
            severity = build_severity(severity=text)
            if severity:
                severities.append(severity)

        elif "not vulnerable" in text_low:
            not_vulnerable = text

        elif "vulnerable" in text_low:
            vulnerable = text

        elif hasattr(child, "attrs"):
            link = child.attrs.get("href")
            if link:
                if "cve.mitre.org" in link:
                    references.append(ReferenceV2(reference_id=text, url=link))
                elif "mailman.nginx.org" in link:
                    references.append(ReferenceV2(url=link))
                elif "/download/patch" in link:
                    link = urljoin("https://nginx.org", link)
                    patch = PatchData(
                        patch_url=link,
                    )
                    patches.append(patch)
                else:
                    link = urljoin("https://nginx.org", link)
                    references.append(ReferenceV2(url=link))

    advisory_id = aliases.pop()
    return NginxAdvisory(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=summary,
        severities=severities,
        not_vulnerable=not_vulnerable,
        vulnerable=vulnerable,
        references=references,
        patches=patches,
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
