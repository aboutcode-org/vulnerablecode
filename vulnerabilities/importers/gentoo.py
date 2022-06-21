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
from typing import Set

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.utils import nearest_patched_package


class GentooImporter(GitImporter):
    def __enter__(self):
        super(GentooImporter, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="xml"
            )

    def updated_advisories(self) -> Set[AdvisoryData]:
        files = self._updated_files.union(self._added_files)
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            advisories.extend(processed_data)
        return self.batch_advisories(advisories)

    def process_file(self, file):
        xml_data = {}
        xml_root = ET.parse(file).getroot()
        glsa = "GLSA-" + xml_root.attrib["id"]
        vuln_reference = [
            Reference(
                reference_id=glsa,
                url="https://security.gentoo.org/glsa/{}".format(xml_root.attrib["id"]),
            )
        ]

        for child in xml_root:
            if child.tag == "references":
                xml_data["cves"] = self.cves_from_reference(child)

            if child.tag == "synopsis":
                xml_data["description"] = child.text

            if child.tag == "affected":
                (
                    xml_data["affected_purls"],
                    xml_data["unaffected_purls"],
                ) = self.affected_and_safe_purls(child)
                xml_data["unaffected_purls"] = list(xml_data["unaffected_purls"])
                xml_data["affected_purls"] = list(xml_data["affected_purls"])

        advisory_list = []
        # It is very inefficient, to create new Advisory for each CVE
        # this way, but there seems no alternative.
        for cve in xml_data["cves"]:
            advisory = AdvisoryData(
                vulnerability_id=cve,
                summary=xml_data["description"],
                affected_packages=nearest_patched_package(
                    xml_data["affected_purls"], xml_data["unaffected_purls"]
                ),
                references=vuln_reference,
            )
            advisory_list.append(advisory)
        return advisory_list

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
        safe_purls = set()
        affected_purls = set()
        skip_versions = {"1.3*", "7.3*", "7.4*"}
        for pkg in affected_elem:
            for info in pkg:
                if info.text in skip_versions:
                    continue
                pkg_ns, pkg_name, = pkg.attrib[
                    "name"
                ].split("/")
                purl = PackageURL(type="ebuild", name=pkg_name, version=info.text, namespace=pkg_ns)

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
                        safe_purls.add(purl)
                    else:
                        affected_purls.add(purl)

                elif info.tag == "vulnerable":
                    if "e" in info.attrib["range"]:
                        affected_purls.add(purl)
                    else:
                        safe_purls.add(purl)

        return (affected_purls, safe_purls)
