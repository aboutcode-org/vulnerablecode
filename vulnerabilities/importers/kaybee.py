#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.utils import load_yaml
from vulnerabilities.utils import nearest_patched_package


class KaybeeImporter(GitImporter):
    def __enter__(self):
        super(KaybeeImporter, self).__enter__()
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
    summary = ""
    if data.get("text"):
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

    return AdvisoryData(
        vulnerability_id=vuln_id,
        summary=summary,
        affected_packages=nearest_patched_package(impacted_packages, resolved_packages),
        references=references,
    )
