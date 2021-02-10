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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from packageurl import PackageURL

from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import Reference
from vulnerabilities.helpers import load_yaml


class KaybeeDataSource(GitDataSource):
    def __enter__(self):
        super(KaybeeDataSource, self).__enter__()
        self._added_files, self._updated_files = self.file_changes(
            recursive=True,
            file_ext="yaml",
        )

    def updated_advisories(self):
        advisories = []
        for yaml_file in self._added_files.union(self._updated_files):
            advisories.append(yaml_file_to_advisory(yaml_file))

        return self.batch_advisories(advisories)


def yaml_file_to_advisory(yaml_path):
    impacted_packages = []
    resolved_packages = []
    references = []

    data = load_yaml(yaml_path)
    vuln_id = data["vulnerability_id"]
    summary = "\n".join([note["text"] for note in data["notes"]])

    for entry in data.get("artifacts", []):
        package = PackageURL.from_string(entry["id"])
        if entry["affected"]:
            impacted_packages.append(package)

        else:
            resolved_packages.append(package)

    for fix in data.get("fixes", []):
        for commit in fix["commits"]:
            references.append(Reference(url=f"{commit['repository']}/{commit['id']}"))

    return Advisory(
        vulnerability_id=vuln_id,
        summary=summary,
        impacted_package_urls=impacted_packages,
        resolved_package_urls=resolved_packages,
        vuln_references=references,
    )
