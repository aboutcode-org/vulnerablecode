#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from pathlib import Path
from typing import Any
from typing import Iterable
from typing import List
from typing import Mapping

from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import AlpineLinuxVersionRange
from univers.versions import InvalidVersion

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.references import WireSharkReferenceV2
from vulnerabilities.references import XsaReferenceV2
from vulnerabilities.references import ZbxReferenceV2
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import load_json


class AlpineLinuxImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect Alpine Linux advisories."""

    pipeline_id = "alpine_linux_importer_v2"
    spdx_license_expression = "CC-BY-SA-4.0"
    license_url = "https://secdb.alpinelinux.org/license.txt"
    repo_url = "git+https://github.com/aboutcode-org/aboutcode-mirror-alpine-secdb/"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
        )

    def advisories_count(self) -> int:
        base_path = Path(self.vcs_response.dest_dir) / "secdb"
        return sum(
            len(pkg.get("advisories", []))
            for data in (load_json(p) for p in base_path.rglob("*.json"))
            for pkg in data.get("packages", [])
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        base_path = Path(self.vcs_response.dest_dir) / "secdb"
        for file_path in base_path.glob("**/*.json"):
            advisory_url = get_advisory_url(
                file=file_path,
                base_path=base_path,
                url="https://secdb.alpinelinux.org/",
            )

            record = load_json(file_path)
            if not record or not record["packages"]:
                self.log(
                    f'"packages" not found in {advisory_url!r}',
                    level=logging.DEBUG,
                )
                continue
            yield from process_record(record=record, url=advisory_url, logger=self.log)

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()


def check_for_attributes(record, logger) -> bool:
    attributes = ["distroversion", "reponame", "archs"]
    for attribute in attributes:
        if attribute not in record:
            logger(
                f'"{attribute!r}" not found in {record!r}',
                level=logging.DEBUG,
            )
            return False
    return True


def process_record(record: dict, url: str, logger: callable) -> Iterable[AdvisoryDataV2]:
    """
    Return a list of AdvisoryData objects by processing data
    present in that `record`
    """
    if not record.get("packages"):
        logger(
            f'"packages" not found in this record {record!r}',
            level=logging.DEBUG,
        )
        return []

    for package in record["packages"]:
        if not package["pkg"]:
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
    logger: callable,
) -> Iterable[AdvisoryDataV2]:
    """
    Yield AdvisoryData by mapping data from `pkg_infos`
    and form PURL for AffectedPackages by using
    `distroversion`, `reponame`, `archs`
    """
    if not pkg_infos.get("name"):
        logger(
            f'"name" is not available in package {pkg_infos!r}',
            level=logging.DEBUG,
        )
        return []

    for version, fixed_vulns in pkg_infos["secfixes"].items():
        if not fixed_vulns:
            logger(
                f"No fixed vulnerabilities in version {version!r}",
                level=logging.DEBUG,
            )
            continue

        # fixed_vulns is a list of strings and each string is a space-separated
        # list of aliases and CVES
        for vuln_ids in fixed_vulns:
            aliases = vuln_ids.strip().split(" ")
            vuln_id = aliases[0]

            references = []
            if vuln_id.startswith("XSA"):
                references.append(XsaReferenceV2.from_id(xsa_id=vuln_id))

            elif vuln_id.startswith("ZBX"):
                references.append(ZbxReferenceV2.from_id(zbx_id=vuln_id))

            elif vuln_id.startswith("wnpa-sec"):
                references.append(WireSharkReferenceV2.from_id(wnpa_sec_id=vuln_id))

            elif vuln_id.startswith("CVE"):
                references.append(
                    ReferenceV2(
                        reference_id=vuln_id,
                        url=f"https://nvd.nist.gov/vuln/detail/{vuln_id}",
                    )
                )

            qualifiers = {
                "distroversion": distroversion,
                "reponame": reponame,
            }

            affected_packages = []

            fixed_version_range = None
            try:
                fixed_version_range = AlpineLinuxVersionRange.from_versions([version])
            except InvalidVersion as e:
                logger(
                    f"{version!r} is not a valid AlpineVersion {e!r}",
                    level=logging.DEBUG,
                )

            if not isinstance(archs, List):
                logger(
                    f"{archs!r} is not of `List` instance",
                    level=logging.DEBUG,
                )
                continue

            if archs and fixed_version_range:
                for arch in archs:
                    qualifiers["arch"] = arch
                    purl = PackageURL(
                        type="apk",
                        namespace="alpine",
                        name=pkg_infos["name"],
                        qualifiers=qualifiers,
                    )
                    affected_packages.append(
                        AffectedPackageV2(
                            package=purl,
                            fixed_version_range=fixed_version_range,
                        )
                    )

            if not archs and fixed_version_range:
                # there is no arch, this is not an arch-specific package
                purl = PackageURL(
                    type="apk",
                    namespace="alpine",
                    name=pkg_infos["name"],
                    qualifiers=qualifiers,
                )
                affected_packages.append(
                    AffectedPackageV2(
                        package=purl,
                        fixed_version_range=fixed_version_range,
                    )
                )

            advisory_id = f"{pkg_infos['name']}/{qualifiers['distroversion']}/{version}/{vuln_id}"
            yield AdvisoryDataV2(
                advisory_id=advisory_id,
                aliases=aliases,
                references=references,
                affected_packages=affected_packages,
                url=url,
            )
