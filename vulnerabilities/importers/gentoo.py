#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable

from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import EbuildVersionRange
from univers.versions import GentooVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference


class GentooImporter(Importer):
    repo_url = "git+https://anongit.gentoo.org/git/data/glsa.git"
    spdx_license_expression = "CC-BY-SA-4.0"
    license_url = "https://anongit.gentoo.org/"

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
        vuln_reference = []
        xml_root = ET.parse(file).getroot()
        id = xml_root.attrib.get("id")
        if id:
            glsa = "GLSA-" + id
            vuln_reference = [
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

        # It is very inefficient, to create new Advisory for each CVE
        # this way, but there seems no alternative.
        for cve in cves:
            yield AdvisoryData(
                aliases=[cve],
                summary=summary,
                references=vuln_reference,
                affected_packages=affected_packages,
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
        safe_versions = set()
        affected_versions = set()
        skip_versions = {"1.3*", "7.3*", "7.4*"}
        for pkg in affected_elem:
            for info in pkg:
                if info.text in skip_versions:
                    continue
                name = pkg.attrib.get("name")
                if name:
                    (
                        pkg_ns,
                        pkg_name,
                    ) = name.split("/")
                purl = PackageURL(type="ebuild", name=pkg_name, namespace=pkg_ns)

                if info.attrib.get("range"):
                    if len(info.attrib.get("range")) > 2:
                        continue

                if info.tag == "unaffected":
                    # quick hack, to know whether this
                    # version lies in this range, 'e' stands for
                    # equal, which is paired with 'greater' or 'less'.
                    # All possible values of info.attrib['range'] =
                    # {'gt', 'lt', 'rle', 'rge', 'rgt', 'le', 'ge', 'eq'}, out of
                    # which ('rle', 'rge', 'rgt') are ignored, because they compare
                    # 'release' not the 'version'.

                    if "e" in info.attrib["range"]:
                        safe_versions.add(info.text)
                    else:
                        affected_versions.add(info.text)

                elif info.tag == "vulnerable":
                    if "e" in info.attrib["range"]:
                        affected_versions.add(info.text)
                    else:
                        safe_versions.add(info.text)

                constraints = []

                for version in safe_versions:
                    constraints.append(
                        VersionConstraint(version=GentooVersion(version), comparator="=").invert()
                    )

                for version in affected_versions:
                    constraints.append(
                        VersionConstraint(version=GentooVersion(version), comparator="=")
                    )

                yield AffectedPackage(
                    package=purl, affected_version_range=EbuildVersionRange(constraints=constraints)
                )
