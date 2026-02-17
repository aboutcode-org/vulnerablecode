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
from traceback import format_exc as traceback_format_exc
from typing import Iterable

from dateutil.parser import parse
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import OpensslVersionRange

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PatchData
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes import openssl
from vulnerabilities.utils import build_description
from vulnerabilities.utils import create_weaknesses_list
from vulnerabilities.utils import get_item
from vulnerabilities.utils import load_json


class OpenSSLImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Import OpenSSL Advisories"""

    pipeline_id = "openssl_importer_v2"
    spdx_license_expression = "Apache-2.0"
    importer_name = "OpenSSL Importer V2"

    license_url = "https://github.com/openssl/openssl/blob/master/LICENSE.txt"
    repo_url = "git+https://github.com/openssl/release-metadata/"

    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)
        self.advisory_path = Path(self.vcs_response.dest_dir)

    def advisories_count(self):
        vuln_directory = self.advisory_path / "secjson"
        return sum(1 for _ in vuln_directory.glob("CVE-*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        vuln_directory = self.advisory_path / "secjson"

        for advisory in vuln_directory.glob("CVE-*.json"):
            yield self.to_advisory_data(advisory)

    def to_advisory_data(self, file: Path) -> Iterable[AdvisoryDataV2]:
        # TODO: Collect the advisory credits, see https://github.com/aboutcode-org/vulnerablecode/issues/2121

        affected_packages = []
        severities = []
        references = []
        patches = []
        fix_commits = {}
        cwe_string = None

        data = load_json(file)
        advisory_text = file.read_text()
        advisory = get_item(data, "containers", "cna")
        description = get_item(advisory, "descriptions", 0, "value")
        title = advisory.get("title")
        date_published = parse(get_item(advisory, "datePublic"))
        cve = get_item(data, "cveMetadata", "cveId")
        severity_score = get_item(advisory, "metrics", 0, "other", "content", "text")

        for reference in get_item(advisory, "references") or []:
            ref_name = reference.get("name")
            ref_url = reference.get("url")
            if not ref_url:
                continue

            tag = get_item(reference, "tags", 0) or ""
            tag = tag.lower()
            references.append(openssl.get_reference(ref_name, tag, ref_url))

            if tag != "patch":
                continue

            if not ref_name:
                patches.append(PatchData(patch_url=ref_url))
                continue

            fix_commits[ref_name.split()[0]] = ref_url

        for affected in get_item(advisory, "affected", 0, "versions") or []:
            if affected.get("status") != "affected":
                continue
            fixed_by_commit_patches = []
            affected_constraints = None
            fixed_version = None

            try:
                affected_constraints, fixed_version = openssl.parse_affected_fixed(affected)
            except Exception as e:
                self.log(
                    f"Failed to parse OpenSSL version for: {cve} with error {e!r}:\n{traceback_format_exc()}",
                    level=logging.ERROR,
                )
                continue

            fixed_version_range = (
                OpensslVersionRange.from_versions([fixed_version]) if fixed_version else None
            )

            affected_version_range = (
                OpensslVersionRange(constraints=affected_constraints)
                if affected_constraints
                else None
            )

            if fixed_version and (commit_url := fix_commits.get(fixed_version)):
                if patch := openssl.get_commit_patch(
                    url=commit_url,
                    logger=self.log,
                ):
                    fixed_by_commit_patches.append(patch)

            affected_packages.append(
                AffectedPackageV2(
                    package=PackageURL(type="openssl", name="openssl"),
                    affected_version_range=affected_version_range,
                    fixed_version_range=fixed_version_range,
                    fixed_by_commit_patches=fixed_by_commit_patches,
                )
            )

        if severity_score:
            severities.append(
                VulnerabilitySeverity(
                    system=severity_systems.OPENSSL,
                    value=severity_score,
                    url=f"https://openssl-library.org/news/secjson/{cve.lower()}.json",
                )
            )

        if "problemTypes" in advisory:
            problem_type = get_item(advisory, "problemTypes", 0, "descriptions", 0)
            cwe_string = problem_type.get("cweId")

        weaknesses = create_weaknesses_list([cwe_string]) if cwe_string else []

        return AdvisoryDataV2(
            advisory_id=cve,
            aliases=[],
            summary=build_description(summary=title, description=description),
            date_published=date_published,
            affected_packages=affected_packages,
            references=references,
            severities=severities,
            weaknesses=weaknesses,
            patches=patches,
            url=f"https://github.com/openssl/release-metadata/blob/main/secjson/{cve}.json",
            original_advisory_text=advisory_text,
        )

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
