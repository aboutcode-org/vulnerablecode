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

import json
import re
from typing import Set
from typing import List

from packageurl import PackageURL

from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.helpers import AffectedPackageWithPatchedPackage


class RetireDotnetDataSource(GitDataSource):
    def __enter__(self):
        super(RetireDotnetDataSource, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, file_ext="json", subdir="./Content"
            )

    def updated_advisories(self) -> Set[Advisory]:
        files = self._updated_files
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.append(processed_data)
        return self.batch_advisories(advisories)

    def added_advisories(self) -> Set[Advisory]:
        files = self._added_files
        advisories = []
        for f in files:
            processed_data = self.process_file(f)
            if processed_data:
                advisories.append(processed_data)
        return self.batch_advisories(advisories)

    @staticmethod
    def vuln_id_from_desc(desc):
        cve_regex = re.compile(r"CVE-\d+-\d+")
        res = cve_regex.search(desc)
        if res:
            return desc[res.start() : res.end()]
        else:
            return None

    def process_file(self, path) -> List[Advisory]:
        with open(path) as f:
            json_doc = json.load(f)
            if self.vuln_id_from_desc(json_doc["description"]):
                vuln_id = self.vuln_id_from_desc(json_doc["description"])
            else:
                return

            affected_packages_with_patched_package = []
            for pkg in json_doc["packages"]:
                affected_packages_with_patched_package.append(
                    AffectedPackageWithPatchedPackage(
                        vulnerable_package=PackageURL(
                            name=pkg["id"], version=pkg["affected"], type="nuget"
                        ),
                        patched_package=PackageURL(
                            name=pkg["id"], version=pkg["fix"], type="nuget"
                        ),
                    )
                )

            vuln_reference = [
                Reference(
                    url=json_doc["link"],
                )
            ]

            return Advisory(
                vulnerability_id=vuln_id,
                summary=json_doc["description"],
                affected_packages_with_patched_package=affected_packages_with_patched_package,
                references=vuln_reference,
            )
