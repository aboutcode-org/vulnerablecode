#
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

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
from vulnerabilities.utils import is_cve

LOGGER = logging.getLogger(__name__)
BASE_URL = "https://secdb.alpinelinux.org/"


class AlpineImporter(Importer):
    spdx_license_expression = "CC-BY-SA-4.0"
    license_url = "https://secdb.alpinelinux.org/license.txt"

    def advisory_data(self) -> Iterable[AdvisoryData]:
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
            yield from process_record(record)


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


def process_record(record: dict) -> Iterable[AdvisoryData]:
    """
    Return a list of AdvisoryData objects by processing data
    present in that `record`
    """
    if not record["packages"]:
        LOGGER.error(f'"packages" not found in this record {record!r}')
        return []

    for package in record["packages"]:
        if not package["pkg"]:
            LOGGER.error(f'"pkg" not found in this package {package!r}')
            continue
        if not check_for_attributes(record):
            continue
        yield from load_advisories(
            package["pkg"],
            record["distroversion"],
            record["reponame"],
            record["archs"],
        )


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
