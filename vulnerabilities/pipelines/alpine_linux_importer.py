#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from typing import Any
from typing import Iterable
from typing import List
from typing import Mapping
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.versions import AlpineLinuxVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.references import WireSharkReference
from vulnerabilities.references import XsaReference
from vulnerabilities.references import ZbxReference
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import is_cve


class AlpineLinuxImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect Alpine Linux advisories."""

    pipeline_id = "alpine_linux_importer"

    spdx_license_expression = "CC-BY-SA-4.0"
    license_url = "https://secdb.alpinelinux.org/license.txt"
    url = "https://secdb.alpinelinux.org/"
    importer_name = "Alpine Linux Importer"

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    def advisories_count(self) -> int:
        return 0

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        page_response_content = fetch_response(self.url).content
        advisory_directory_links = fetch_advisory_directory_links(
            page_response_content, self.url, self.log
        )
        advisory_links = []
        for advisory_directory_link in advisory_directory_links:
            advisory_directory_page = fetch_response(advisory_directory_link).content
            advisory_links.extend(
                fetch_advisory_links(advisory_directory_page, advisory_directory_link, self.log)
            )
        for link in advisory_links:
            record = fetch_response(link).json()
            if not record["packages"]:
                self.log(
                    f'"packages" not found in {link!r}',
                    level=logging.DEBUG,
                )
                continue
            yield from process_record(record=record, url=link, logger=self.log)


def fetch_advisory_directory_links(
    page_response_content: str,
    base_url: str,
    logger: callable = None,
) -> List[str]:
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
        if logger:
            logger(
                f"No versions found in {base_url!r}",
                level=logging.DEBUG,
            )
        return []

    advisory_directory_links = [urljoin(base_url, version) for version in alpine_versions]

    return advisory_directory_links


def fetch_advisory_links(
    advisory_directory_page: str,
    advisory_directory_link: str,
    logger: callable = None,
) -> Iterable[str]:
    """
    Yield json file urls present in `advisory_directory_page`
    """
    advisory_directory_page = BeautifulSoup(advisory_directory_page, features="lxml")
    anchor_tags = advisory_directory_page.find_all("a")
    if not anchor_tags:
        if logger:
            logger(
                f"No anchor tags found in {advisory_directory_link!r}",
                level=logging.DEBUG,
            )
        return iter([])
    for anchor_tag in anchor_tags:
        if anchor_tag.text.endswith("json"):
            yield urljoin(advisory_directory_link, anchor_tag.text)


def check_for_attributes(record, logger) -> bool:
    attributes = ["distroversion", "reponame", "archs"]
    for attribute in attributes:
        if attribute not in record:
            if logger:
                logger(
                    f'"{attribute!r}" not found in {record!r}',
                    level=logging.DEBUG,
                )
            return False
    return True


def process_record(record: dict, url: str, logger: callable = None) -> Iterable[AdvisoryData]:
    """
    Return a list of AdvisoryData objects by processing data
    present in that `record`
    """
    if not record.get("packages"):
        if logger:
            logger(
                f'"packages" not found in this record {record!r}',
                level=logging.DEBUG,
            )
        return []

    for package in record["packages"]:
        if not package["pkg"]:
            if logger:
                logger(
                    f'"pkg" not found in this package {package!r}',
                    level=logging.DEBUG,
                )
            continue
        if not check_for_attributes(record, logger):
            continue
        yield from load_advisories(
            pkg_infos=package["pkg"],
            distroversion=record["distroversion"],
            reponame=record["reponame"],
            archs=record["archs"],
            url=url,
            logger=logger,
        )


def load_advisories(
    pkg_infos: Mapping[str, Any],
    distroversion: str,
    reponame: str,
    archs: List[str],
    url: str,
    logger: callable = None,
) -> Iterable[AdvisoryData]:
    """
    Yield AdvisoryData by mapping data from `pkg_infos`
    and form PURL for AffectedPackages by using
    `distroversion`, `reponame`, `archs`
    """
    if not pkg_infos.get("name"):
        if logger:
            logger(
                f'"name" is not available in package {pkg_infos!r}',
                level=logging.DEBUG,
            )
        return []

    for version, fixed_vulns in pkg_infos["secfixes"].items():
        if not fixed_vulns:
            if logger:
                logger(
                    f"No fixed vulnerabilities in version {version!r}",
                    level=logging.DEBUG,
                )
            continue
        # fixed_vulns is a list of strings and each string is a space-separated
        # list of aliases and CVES
        for vuln_ids in fixed_vulns:
            if not isinstance(vuln_ids, str):
                if logger:
                    logger(
                        f"{vuln_ids!r} is not of `str` instance",
                        level=logging.DEBUG,
                    )
                continue
            vuln_ids = vuln_ids.strip().split()
            if not vuln_ids:
                if logger:
                    logger(
                        f"{vuln_ids!r} is empty",
                        level=logging.DEBUG,
                    )
                continue
            aliases = vuln_ids

            references = []
            for reference_id in vuln_ids:

                if reference_id.startswith("XSA"):
                    references.append(XsaReference.from_id(xsa_id=reference_id))

                elif reference_id.startswith("ZBX"):
                    references.append(ZbxReference.from_id(zbx_id=reference_id))

                elif reference_id.startswith("wnpa-sec"):
                    references.append(WireSharkReference.from_id(wnpa_sec_id=reference_id))

                elif not reference_id.startswith("CVE"):
                    if logger:
                        logger(f"Unknown reference id {reference_id!r}", level=logging.DEBUG)

            qualifiers = {
                "distroversion": distroversion,
                "reponame": reponame,
            }

            affected_packages = []

            try:
                fixed_version = AlpineLinuxVersion(version)
            except Exception as e:
                if logger:
                    logger(
                        f"{version!r} is not a valid AlpineVersion {e!r}",
                        level=logging.DEBUG,
                    )
                continue
            if not isinstance(archs, List):
                if logger:
                    logger(
                        f"{archs!r} is not of `List` instance",
                        level=logging.DEBUG,
                    )
                continue
            if archs:
                for arch in archs:
                    qualifiers["arch"] = arch
                    affected_packages.append(
                        AffectedPackage(
                            package=PackageURL(
                                type="apk",
                                namespace="alpine",
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
                            type="apk",
                            namespace="alpine",
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
                url=url,
            )
