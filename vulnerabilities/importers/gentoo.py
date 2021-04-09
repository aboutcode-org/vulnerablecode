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

import re
import xml.etree.ElementTree as ET
from typing import Set

from packageurl import PackageURL

from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.helpers import nearest_patched_package


class GentooDataSource(GitDataSource):
    def __enter__(self):
        super(GentooDataSource, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="xml"
            )

    def updated_advisories(self) -> Set[Advisory]:
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
            advisory = Advisory(
                vulnerability_id=cve,
                summary=xml_data["description"],
                affected_packages_with_patched_package=nearest_patched_package(
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

        for pkg in affected_elem:
            for info in pkg:
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
