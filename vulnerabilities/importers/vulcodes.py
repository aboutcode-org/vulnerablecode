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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import json

from packageurl import PackageURL

from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference


class VulCodeDataSource(GitDataSource):
    def __enter__(self):
        super(VulCodeDataSource, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                file_ext="json",
            )

    def updated_advisories(self):

        advisories = []
        for file in self._added_files.union(self._updated_files):
            with open(file) as f:
                data = json.load(f)
                references = []

                for ref in data["references"]:
                    references.append(Reference(url=ref["url"], reference_id=ref["reference_id"]))

                advisories.append(
                    Advisory(
                        identifier=data["identifier"],
                        summary=data["summary"],
                        impacted_package_urls=[
                            PackageURL.from_string(purl) for purl in data["vulnerable_packages"]
                        ],
                        resolved_package_urls=[
                            PackageURL.from_string(purl) for purl in data["resolved_packages"]
                        ],
                        vuln_references=references,
                    )
                )

        return self.batch_advisories(advisories)
