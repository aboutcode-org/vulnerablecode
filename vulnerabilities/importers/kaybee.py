#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from pathlib import Path
from typing import Iterable

from packageurl import PackageURL
from univers import version_range

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.utils import load_yaml

logger = logging.getLogger(__name__)


class KaybeeImporter(Importer):
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/SAP/project-kb/blob/main/LICENSE.txt"
    repo_url = "git+https://github.com/SAP/project-kb.git@vulnerability-data"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone(self.repo_url)
            base_path = Path(self.vcs_response.dest_dir)
            statements = base_path.glob("statements/**/*.yaml")
            for statement_file in statements:
                yield yaml_file_to_advisory(statement_file)

        finally:
            if self.vcs_response:
                self.vcs_response.delete()


def yaml_file_to_advisory(yaml_path):
    references = []

    data = load_yaml(yaml_path)
    aliases = []
    vuln_id = data.get("vulnerability_id")
    if vuln_id:
        aliases.append(vuln_id)
    summary = ""
    notes = data.get("notes")
    if notes:
        note_texts = []
        for note in notes:
            note_text = note.get("text")
            if note_text:
                note_texts.append(note_text)
        summary = "\n".join(note_texts)

    affected_packages = []

    for entry in data.get("artifacts", []):
        purl = entry.get("id")
        if not purl:
            continue
        package = PackageURL.from_string(purl)
        version = package.version
        affected_version_range = None
        fixed_version = None
        vrc = version_range.RANGE_CLASS_BY_SCHEMES.get(package.type)
        if not vrc:
            logger.warning(f"Unknown package type {package.type} for {purl} in {vuln_id}")
            continue
        if entry.get("affected"):
            affected_version_range = vrc.from_versions([version])
        else:
            fixed_version = vrc.version_class(version)
        versionless_purl = PackageURL(
            type=package.type,
            namespace=package.namespace,
            name=package.name,
            qualifiers=package.qualifiers,
            subpath=package.subpath,
        )
        affected_packages.append(
            AffectedPackage(
                package=versionless_purl,
                affected_version_range=affected_version_range,
                fixed_version=fixed_version,
            )
        )

    for fix in data.get("fixes") or []:
        for commit in fix.get("commits") or []:
            references.append(Reference(url=f"{commit['repository']}/{commit['id']}"))

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        affected_packages=affected_packages,
        references=references,
    )
