#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.
import logging
from typing import Any
from typing import Iterable
from typing import List
from typing import Mapping
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from django.db.models.query import QuerySet
from packageurl import PackageURL
from univers.versions import AlpineLinuxVersion

from vulnerabilities.helpers import is_cve
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.references import WireSharkReference
from vulnerabilities.references import XsaReference
from vulnerabilities.references import ZbxReference

LOGGER = logging.getLogger(__name__)
BASE_URL = "https://secdb.alpinelinux.org/"


class AlpineImporter(Importer):
    spdx_license_expression = "CC-BY-SA-4.0"
    license_url = "https://secdb.alpinelinux.org/license.txt"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        advisories = []
        page_response_content = fetch_response(BASE_URL).content
        advisory_directory_links = fetch_advisory_directory_links(page_response_content)
        advisory_links = []
        for advisory_directory_link in advisory_directory_links:
            advisory_directory_page = fetch_response(advisory_directory_link).content
            advisory_links.extend(
                fetch_advisory_links(advisory_directory_page, advisory_directory_link)
            )
        for link in advisory_links:
            record = fetch_response(link).json()
            if not record["packages"]:
                LOGGER.error(f'"packages" not found in {link!r}')
                continue
            advisories.extend(process_record(record))
        return advisories


def fetch_response(url):
    """
    Fetch and return `response` from the `url`
    """
    response = requests.get(url)
    if response.status_code == 200:
        return response
    raise Exception(f"Failed to fetch data from {url!r} with status code: {response.status_code!r}")


def fetch_advisory_directory_links(page_response_content: str) -> List[str]:
    """
    Return a list of advisory directory links present in `page_response_content` html string
    """
    index_page = BeautifulSoup(page_response_content, features="lxml")
    alpine_versions = [
        link.text
        for link in index_page.find_all("a")
        if link.text.startswith("v") or link.text.startswith("edge")
    ]

    if not alpine_versions:
        LOGGER.error(f"No versions found in {BASE_URL!r}")
        return []

    advisory_directory_links = [urljoin(BASE_URL, version) for version in alpine_versions]

    return advisory_directory_links


def fetch_advisory_links(
    advisory_directory_page: str, advisory_directory_link: str
) -> Iterable[str]:
    """
    Yield json file urls present in `advisory_directory_page`
    """
    advisory_directory_page = BeautifulSoup(advisory_directory_page, features="lxml")
    anchor_tags = advisory_directory_page.find_all("a")
    if not anchor_tags:
        LOGGER.error(f"No anchor tags found in {advisory_directory_link!r}")
        return iter([])
    for anchor_tag in anchor_tags:
        if anchor_tag.text.endswith("json"):
            yield urljoin(advisory_directory_link, anchor_tag.text)


def check_for_attributes(record) -> bool:
    attributes = ["distroversion", "reponame", "archs"]
    for attribute in attributes:
        if attribute not in record:
            LOGGER.error(f'"{attribute!r}" not found in {record!r}')
            return False
    return True


def process_record(record: dict) -> List[AdvisoryData]:
    """
    Return a list of AdvisoryData objects by processing data
    present in that `record`
    """
    if not record["packages"]:
        LOGGER.error(f'"packages" not found in this record {record!r}')
        return []

    advisories: List[AdvisoryData] = []

    for package in record["packages"]:
        if not package["pkg"]:
            LOGGER.error(f'"pkg" not found in this package {package!r}')
            continue
        if not check_for_attributes(record):
            continue
        loaded_advisories = load_advisories(
            package["pkg"],
            record["distroversion"],
            record["reponame"],
            record["archs"],
        )
        advisories.extend(loaded_advisories)
    return advisories


def load_advisories(
    pkg_infos: Mapping[str, Any],
    distroversion: str,
    reponame: str,
    archs: List[str],
) -> Iterable[AdvisoryData]:
    """
    Yield AdvisoryData by mapping data from `pkg_infos`
    and form PURL for AffectedPackages by using
    `distroversion`, `reponame`, `archs`
    """
    if not pkg_infos.get("name"):
        LOGGER.error(f'"name" is not available in package {pkg_infos!r}')
        return []

    for version, fixed_vulns in pkg_infos["secfixes"].items():
        if not fixed_vulns:
            LOGGER.error(f"No fixed vulnerabilities in version {version!r}")
            continue

        for vuln_ids in fixed_vulns:
            if not isinstance(vuln_ids, str):
                LOGGER.error(f"{vuln_ids!r} is not of `str` instance")
                continue
            vuln_ids = vuln_ids.split()
            aliases = []
            vuln_id = vuln_ids[0]
            # check for valid vuln ID, if there is valid vuln ID then iterate over
            # the remaining elements of the list else iterate over the whole list
            # and also check if the initial element is a reference or not
            if is_cve(vuln_id):
                aliases = [vuln_id]
                vuln_ids = vuln_ids[1:]
            references = []
            for reference_id in vuln_ids:

                if reference_id.startswith("XSA"):
                    references.append(XsaReference.from_id(xsa_id=reference_id))

                elif reference_id.startswith("ZBX"):
                    references.append(ZbxReference.from_id(zbx_id=reference_id))

                elif reference_id.startswith("wnpa-sec"):
                    references.append(WireSharkReference.from_id(wnpa_sec_id=reference_id))

            qualifiers = {
                "distroversion": distroversion,
                "reponame": reponame,
            }

            affected_packages = []

            try:
                fixed_version = AlpineLinuxVersion(version)
            except Exception as e:
                LOGGER.error(f"{version!r} is not a valid AlpineVersion {e!r}")
                continue
            if not isinstance(archs, List):
                LOGGER.error(f"{archs!r} is not of `List` instance")
                continue
            if archs:
                for arch in archs:
                    qualifiers["arch"] = arch
                    affected_packages.append(
                        AffectedPackage(
                            package=PackageURL(
                                type="alpine",
                                name=pkg_infos["name"],
                                qualifiers=qualifiers,
                            ),
                            fixed_version=fixed_version,
                        )
                    )
            else:
                # there is no arch, this is not an arch-specific package
                affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(
                            type="alpine",
                            name=pkg_infos["name"],
                            qualifiers=qualifiers,
                        ),
                        fixed_version=fixed_version,
                    )
                )

            yield AdvisoryData(
                references=references,
                affected_packages=affected_packages,
                aliases=aliases,
            )


class AlpineBasicImprover(Improver):
    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(created_by=AlpineImporter.qualified_name)

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        """
        Generate and return Inferences for the given advisory data
        """
        for affected_package in advisory_data.affected_packages:
            fixed_purl = affected_package.get_fixed_purl()
            yield Inference.from_advisory_data(
                advisory_data,
                confidence=MAX_CONFIDENCE,
                fixed_purl=fixed_purl,
            )
