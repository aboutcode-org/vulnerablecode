#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import EbuildVersionRange
from univers.versions import GentooVersion
from univers.versions import InvalidVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference

logger = logging.getLogger(__name__)
RANGE_TO_COMPARATOR = {
    "lt": "<",
    "gt": ">",
    "le": "<=",
    "ge": ">=",
    "eq": "=",
    "rlt": "<",
    "rgt": ">",
    "rle": "<=",
    "rge": ">=",
}


class GentooImporter(Importer):
    repo_url = "git+https://anongit.gentoo.org/git/data/glsa.git"
    spdx_license_expression = "CC-BY-SA-4.0"
    # the license notice is at this url https://anongit.gentoo.org/ says:
    # The contents of this document, unless otherwise expressly stated, are licensed
    # under the [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/) license.
    license_url = "https://creativecommons.org/licenses/by-sa/4.0/"
    importer_name = "Gentoo Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone(repo_url=self.repo_url)
            base_path = Path(self.vcs_response.dest_dir)
            for file_path in base_path.glob("**/*.xml"):
                yield from self.process_file(file_path)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def process_file(self, file):
        cves = []
        summary = ""
        vuln_references = []
        xml_root = ET.parse(file).getroot()
        id = xml_root.attrib.get("id")
        if id:
            glsa = "GLSA-" + id
            vuln_references = [
                Reference(
                    reference_id=glsa,
                    url=f"https://security.gentoo.org/glsa/{id}",
                )
            ]

        for child in xml_root:
            if child.tag == "references":
                cves = self.cves_from_reference(child)

            if child.tag == "synopsis":
                summary = child.text

            if child.tag == "affected":
                affected_packages = list(self.affected_and_safe_purls(child))
        for cve in cves:
            yield AdvisoryData(
                aliases=[cve],
                summary=summary,
                references=vuln_references,
                affected_packages=affected_packages,
                url=(
                    f"https://security.gentoo.org/glsa/{id}"
                    if id
                    else "https://security.gentoo.org/glsa"
                ),
            )

    @staticmethod
    def cves_from_reference(reference):
        cves = []
        for child in reference:
            txt = child.text.strip()
            match = re.match(r"CVE-\d{4}-\d{4,}", txt)
            if match:
                cves.append(match.group())

        return cves

    @staticmethod
    def affected_and_safe_purls(affected_elem):
        skip_versions = {"1.3*", "7.3*", "7.4*"}
        for pkg in affected_elem:
            name = pkg.attrib.get("name")
            if not name:
                continue
            pkg_ns, _, pkg_name = name.rpartition("/")
            purl = PackageURL(type="ebuild", name=pkg_name, namespace=pkg_ns)

            constraints = []
            for info in pkg:
                if info.tag not in ("unaffected", "vulnerable"):
                    continue

                version_str = info.text.strip() if info.text else ""
                if not version_str or version_str in skip_versions:
                    continue

                range_op = info.attrib.get("range")
                if not range_op:
                    continue

                comparator = RANGE_TO_COMPARATOR.get(range_op)
                if not comparator:
                    logger.error(f"Unknown Gentoo range operator: {range_op!r}")
                    continue

                try:
                    version = GentooVersion(version_str)
                except InvalidVersion as e:
                    logger.error(f"Invalid version {version_str!r}: {e}")
                    continue

                constraint = VersionConstraint(version=version, comparator=comparator)

                if info.tag == "unaffected":
                    constraint = constraint.invert()

                constraints.append(constraint)

            if not constraints:
                continue

            yield AffectedPackage(
                package=purl,
                affected_version_range=EbuildVersionRange(constraints=constraints),
            )
