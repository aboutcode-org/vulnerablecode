# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import dataclasses
import datetime
from typing import Iterable
import logging

import asyncio
import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import NginxVersionRange
from univers.versions import SemverVersion
from django.db.models.query import QuerySet

from vulnerabilities.data_source import AdvisoryData
from vulnerabilities.data_source import AffectedPackage
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.data_inference import Inference
from vulnerabilities.data_inference import Improver
from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.models import Advisory
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.package_managers import Version
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)


@dataclasses.dataclass
class NginxDataSourceConfiguration(DataSourceConfiguration):
    etags: dict


class NginxDataSource(DataSource):
    CONFIG_CLASS = NginxDataSourceConfiguration

    url = "http://nginx.org/en/security_advisories.html"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        data = requests.get(self.url).content
        soup = BeautifulSoup(data, features="lxml")
        vuln_list = soup.select("li p")
        for vuln_info in vuln_list:
            yield to_advisory_data(**parse_advisory_data_from_paragraph(vuln_info))


def to_advisory_data(
    aliases, summary, advisory_severity, not_vulnerable, vulnerable, references
) -> AdvisoryData:
    """
    Return AdvisoryData formed by given parameters
    An advisory paragraph, without html markup, looks like:

    1-byte memory overwrite in resolver
    Severity: medium
    Advisory
    CVE-2021-23017
    Not vulnerable: 1.21.0+, 1.20.1+
    Vulnerable: 0.6.18-1.20.0
    The patch  pgp
    """

    qualifiers = {}

    affected_version_range = vulnerable.partition(":")[2]
    if "nginx/Windows" in affected_version_range:
        qualifiers["os"] = "windows"
        affected_version_range = affected_version_range.replace("nginx/Windows", "")
    affected_version_range = NginxVersionRange.from_native(affected_version_range)

    affected_packages = []
    _, _, fixed_versions = not_vulnerable.partition(":")
    for fixed_version in fixed_versions.split(","):
        fixed_version = fixed_version.rstrip("+")

        # TODO: Mail nginx for this anomaly (create ticket on our side)
        if "none" in fixed_version:
            affected_packages.append(
                AffectedPackage(
                    package=PackageURL(type="generic", name="nginx", qualifiers=qualifiers),
                    affected_version_range=affected_version_range,
                )
            )
            break

        fixed_version = SemverVersion(fixed_version)
        purl = PackageURL(type="generic", name="nginx", qualifiers=qualifiers)
        affected_packages.append(
            AffectedPackage(
                package=purl,
                affected_version_range=affected_version_range,
                fixed_version=fixed_version,
            )
        )

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        affected_packages=affected_packages,
        references=references,
    )


def parse_advisory_data_from_paragraph(vuln_info):
    """
    Return a dict with keys (aliases, summary, advisory_severity,
    not_vulnerable, vulnerable, references) from bs4 paragraph

    For example:
    >>> paragraph = '<p>1-byte memory overwrite in resolver<br/>Severity: medium<br/><a href="http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html">Advisory</a><br/><a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017">CVE-2021-23017</a><br/>Not vulnerable: 1.21.0+, 1.20.1+<br/>Vulnerable: 0.6.18-1.20.0<br/><a href="/download/patch.2021.resolver.txt">The patch</a>  <a href="/download/patch.2021.resolver.txt.asc">pgp</a></p>'
    >>> vuln_info = BeautifulSoup(paragraph, features="lxml").p
    >>> parse_advisory_data_from_paragraph(vuln_info)
    {'aliases': ['CVE-2021-23017'], 'summary': '1-byte memory overwrite in resolver', 'advisory_severity': 'Severity: medium', 'not_vulnerable': 'Not vulnerable: 1.21.0+, 1.20.1+', 'vulnerable': 'Vulnerable: 0.6.18-1.20.0', 'references': [Reference(reference_id='', url='http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html', severities=[VulnerabilitySeverity(system=ScoringSystem(identifier='generic_textual', name='Generic textual severity rating', url='', notes='Severity for unknown scoring systems. Contains generic textual values like High, Low etc'), value='Severity: medium')]), Reference(reference_id='', url='https://nginx.org/download/patch.2021.resolver.txt', severities=[]), Reference(reference_id='', url='https://nginx.org/download/patch.2021.resolver.txt.asc', severities=[])]}
    """
    aliases = []
    summary = advisory_severity = not_vulnerable = vulnerable = None
    references = []
    is_first = True
    for child in vuln_info.children:
        if is_first:
            summary = child
            is_first = False

        elif child.text.startswith(
            (
                "CVE-",
                "CORE-",
                "VU#",
            )
        ):
            aliases.append(child.text)

        elif "severity" in child.text.lower():
            advisory_severity = child.text

        elif "not vulnerable" in child.text.lower():
            not_vulnerable = child.text

        elif "vulnerable" in child.text.lower():
            vulnerable = child.text

        elif hasattr(child, "attrs") and child.attrs.get("href"):
            link = child.attrs["href"]
            # Take care of relative urls
            link = requests.compat.urljoin("https://nginx.org", link)
            if "cve.mitre.org" in link:
                cve = child.text.strip()
                reference = Reference(reference_id=cve, url=link)
                references.append(reference)
            elif "http://mailman.nginx.org" in link:
                ss = SCORING_SYSTEMS["generic_textual"]
                severity = VulnerabilitySeverity(system=ss, value=advisory_severity)
                references.append(Reference(url=link, severities=[severity]))
            else:
                references.append(Reference(url=link))

    return {
        "aliases": aliases,
        "summary": summary,
        "advisory_severity": advisory_severity,
        "not_vulnerable": not_vulnerable,
        "vulnerable": vulnerable,
        "references": references,
    }


class NginxBasicImprover(Improver):
    def __init__(self):
        self.set_api()

    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(created_by=NginxDataSource.qualified_name())

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        """
        Generate and return Inferences for the given advisory data
        """
        try:
            purl, affected_version_ranges, fixed_versions = AffectedPackage.merge(
                advisory_data.affected_packages
            )
        except KeyError:
            return iter([])
        all_versions = self.version_api.get("nginx/nginx").valid_versions
        affected_purls = []
        for affected_version_range in affected_version_ranges:
            for version in all_versions:
                version = SemverVersion(version)
                if is_vulnerable(
                    version=version,
                    affected_version_range=affected_version_range,
                    fixed_versions=fixed_versions,
                ):
                    affected_purls.append(purl._replace(version=version))

        for fixed_version in fixed_versions:
            # TODO: This also yields with a lower fixed version, maybe we should
            # only yield fixes that are upgrades ?
            fixed_purl = purl._replace(version=fixed_version)
            yield Inference.from_advisory_data(
                advisory_data,
                confidence=90,  # TODO: Decide properly
                affected_purls=affected_purls,
                fixed_purl=fixed_purl,
            )

    def set_api(self):
        self.version_api = GitHubTagsAPI()
        asyncio.run(self.version_api.load_api(["nginx/nginx"]))

        # Nginx tags it's releases are in the form of `release-1.2.3`
        # Chop off the `release-` part here.
        normalized_versions = set()
        while self.version_api.cache["nginx/nginx"]:
            version = self.version_api.cache["nginx/nginx"].pop()
            normalized_version = Version(
                version.value.replace("release-", ""), version.release_date
            )
            normalized_versions.add(normalized_version)
        self.version_api.cache["nginx/nginx"] = normalized_versions


def is_vulnerable(version, affected_version_range, fixed_versions):
    # Check if the version is in "Vulnerable" range.  If it's not, the
    # version is not vulnerable.
    #
    # If it is, check if the branch is explicitly listed in the "Not
    # vulnerable".  If it's not, the version is vulnerable.  If it
    # is, check the minor number: if it's greater or equal to the
    # version listed as not vulnerable, the version is not vulnerable,
    # else the version is vulnerable.
    #
    # See: https://marc.info/?l=nginx&m=164070162912710&w=2
    if version in NginxVersionRange.from_string(affected_version_range.to_string()):
        for fixed_version in fixed_versions:
            if version.value.minor == fixed_version.value.minor and version >= fixed_version:
                return False
        return True
    return False
