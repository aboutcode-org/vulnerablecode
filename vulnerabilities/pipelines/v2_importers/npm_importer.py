#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# Author: Navonil Das (@NavonilDas)

import json
from pathlib import Path
from typing import Iterable

import pytz
from dateutil.parser import parse
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import NpmVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import CVSSV2
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.utils import build_description
from vulnerabilities.utils import load_json


class NpmImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Node.js Security Working Group importer pipeline

    Import advisories from nodejs security working group including node proper advisories and npm advisories.
    """

    pipeline_id = "nodejs_security_wg"
    spdx_license_expression = "MIT"
    license_url = "https://github.com/nodejs/security-wg/blob/main/LICENSE.md"
    repo_url = "git+https://github.com/nodejs/security-wg"
    unfurl_version_ranges = True

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

    def advisories_count(self):
        vuln_directory = Path(self.vcs_response.dest_dir) / "vuln" / "npm"
        return sum(1 for _ in vuln_directory.glob("*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        vuln_directory = Path(self.vcs_response.dest_dir) / "vuln" / "npm"

        for advisory in vuln_directory.glob("*.json"):
            yield self.to_advisory_data(advisory)

    def to_advisory_data(self, file: Path) -> Iterable[AdvisoryData]:
        if file.name == "index.json":
            self.log(f"Skipping {file.name} file")
            return
        data = load_json(file)
        advisory_text = None
        with open(file) as f:
            advisory_text = f.read()
        id = data.get("id")
        description = data.get("overview") or ""
        summary = data.get("title") or ""
        # TODO: Take care of description
        date_published = None
        if isinstance(data.get("created_at"), str):
            date_published = parse(data.get("created_at")).replace(tzinfo=pytz.UTC)
        references = []
        cvss_vector = data.get("cvss_vector")
        cvss_score = data.get("cvss_score")
        severities = []
        if cvss_vector and cvss_vector.startswith("CVSS:3.0/"):
            severities.append(
                VulnerabilitySeverity(
                    system=CVSSV3,
                    value=cvss_score,
                    url=f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/{id}.json",
                )
            )
        if cvss_vector and cvss_vector.startswith("CVSS:2.0/"):
            severities.append(
                VulnerabilitySeverity(
                    system=CVSSV2,
                    value=cvss_score,
                    url=f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/{id}.json",
                )
            )
        if not id:
            self.log(f"Advisory ID not found in {file}")
            return

        advisory_reference = ReferenceV2(
            url=f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/{id}.json",
            reference_id=id,
        )

        for ref in data.get("references") or []:
            references.append(
                ReferenceV2(
                    url=ref,
                )
            )

        if advisory_reference not in references:
            references.append(advisory_reference)

        package_name = data.get("module_name")
        affected_packages = []
        if package_name:
            affected_packages.append(self.get_affected_package(data, package_name))
        advsisory_aliases = data.get("cves") or []

        return AdvisoryData(
            advisory_id=f"npm-{id}",
            aliases=advsisory_aliases,
            summary=build_description(summary=summary, description=description),
            date_published=date_published,
            affected_packages=affected_packages,
            references_v2=references,
            severities=severities,
            url=f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/{id}.json",
            original_advisory_text=advisory_text or json.dumps(data, indent=2, ensure_ascii=False),
        )

    def get_affected_package(self, data, package_name):
        affected_version_range = None
        unaffected_version_range = None
        fixed_version = None

        vulnerable_range = data.get("vulnerable_versions") or ""
        patched_range = data.get("patched_versions") or ""

        # https://github.com/nodejs/security-wg/blob/cfaa51cc5c83f01eea61b69658f7bc76a77c5979/vuln/npm/213.json#L14
        if vulnerable_range == "<=99.999.99999":
            vulnerable_range = "*"
        if vulnerable_range:
            affected_version_range = NpmVersionRange.from_native(vulnerable_range)

        # https://github.com/nodejs/security-wg/blob/cfaa51cc5c83f01eea61b69658f7bc76a77c5979/vuln/npm/213.json#L15
        if patched_range == "<0.0.0":
            patched_range = None
        if patched_range:
            unaffected_version_range = NpmVersionRange.from_native(patched_range)

        # We only store single fixed versions and not a range of fixed versions
        # If there is a single constraint in the unaffected_version_range
        # having comparator as ">=" then we store that as the fixed version
        if unaffected_version_range and len(unaffected_version_range.constraints) == 1:
            constraint = unaffected_version_range.constraints[0]
            if constraint.comparator == ">=":
                fixed_version = constraint.version

        return AffectedPackage(
            package=PackageURL(
                type="npm",
                name=package_name,
            ),
            affected_version_range=affected_version_range,
            fixed_version=fixed_version,
        )

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
