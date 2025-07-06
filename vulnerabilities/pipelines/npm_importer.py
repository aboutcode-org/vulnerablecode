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
import os
import tempfile
from pathlib import Path
from typing import Iterable

import pytz
import requests
from dateutil.parser import parse
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.severity_systems import CVSSV2
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.utils import build_description
from vulnerabilities.utils import load_json


class NpmImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect advisories from nodejs GitHub repository."""

    pipeline_id = "npm_importer"

    spdx_license_expression = "MIT"
    license_url = "https://github.com/nodejs/security-wg/blob/main/LICENSE.md"
    repo_url = "git+https://github.com/nodejs/security-wg"
    importer_name = "Npm Importer"

    is_batch_run = True

    def __init__(self, *args, purl=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.purl = purl
        if self.purl:
            NpmImporterPipeline.is_batch_run = False
            if self.purl.type != "npm":
                print(f"Warning: This importer handles NPM packages. Current PURL: {self.purl!s}")

    @classmethod
    def steps(cls):
        if not cls.is_batch_run:
            return [
                cls.fetch_package_advisories,
                cls.collect_and_store_advisories,
                cls.import_new_advisories,
            ]

        return [
            cls.clone,
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
            cls.clean_downloads,
        ]

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def fetch_package_advisories(self):
        if not self.purl or self.purl.type != "npm":
            return

        self.log(f"Fetching advisories for package {self.purl.name}")

        package_name = self.purl.name

        self.temp_dir = tempfile.mkdtemp()
        self.package_advisories = []

        api_url = "https://api.github.com/repos/nodejs/security-wg/contents/vuln/npm"
        response = requests.get(api_url)

        if response.status_code != 200:
            self.log(f"Failed to fetch advisories directory: {response.status_code}")
            return

        for item in response.json():
            if item["type"] == "file" and item["name"].endswith(".json"):
                file_url = item["download_url"]
                try:
                    file_content = requests.get(file_url).json()

                    if file_content.get("module_name") == package_name:
                        file_path = os.path.join(self.temp_dir, item["name"])
                        with open(file_path, "w") as f:
                            json.dump(file_content, f)
                        self.package_advisories.append(file_path)
                except Exception as e:
                    self.log(f"Error processing advisory file {item['name']}: {str(e)}")

        self.log(f"Found {len(self.package_advisories)} advisories for package {package_name}")

    def advisories_count(self):
        if NpmImporterPipeline.is_batch_run:
            vuln_directory = Path(self.vcs_response.dest_dir) / "vuln" / "npm"
            return sum(1 for _ in vuln_directory.glob("*.json"))
        else:
            return len(getattr(self, "package_advisories", []))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        if NpmImporterPipeline.is_batch_run:
            vuln_directory = Path(self.vcs_response.dest_dir) / "vuln" / "npm"
            for advisory in vuln_directory.glob("*.json"):
                yield from self.to_advisory_data(advisory)
        else:
            if not hasattr(self, "package_advisories"):
                return

            for advisory_path in self.package_advisories:
                yield from self.to_advisory_data(Path(advisory_path))

    def to_advisory_data(self, file: Path) -> Iterable[AdvisoryData]:
        data = load_json(file)
        id = data.get("id")
        description = data.get("overview") or ""
        summary = data.get("title") or ""
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
                )
            )
        if cvss_vector and cvss_vector.startswith("CVSS:2.0/"):
            severities.append(
                VulnerabilitySeverity(
                    system=CVSSV2,
                    value=cvss_score,
                )
            )

        advisory_reference = Reference(
            url=f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/{id}.json",
            reference_id=id,
            severities=severities,
        )

        for ref in data.get("references") or []:
            references.append(
                Reference(
                    url=ref,
                    severities=severities,
                )
            )

        if advisory_reference not in references:
            references.append(advisory_reference)

        package_name = data.get("module_name")
        affected_packages = []
        if package_name:
            affected_packages.append(self.get_affected_package(data, package_name))
        advsisory_aliases = data.get("cves") or []

        if self.purl and self.purl.version:
            affected_package = affected_packages[0] if affected_packages else None
            if affected_package and not self._version_is_affected(affected_package):
                return

        for alias in advsisory_aliases:
            yield AdvisoryData(
                summary=build_description(summary=summary, description=description),
                references=references,
                date_published=date_published,
                affected_packages=affected_packages,
                aliases=[alias],
                url=f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/{id}.json",
            )

    def _version_is_affected(self, affected_package):
        if not self.purl.version or not affected_package.affected_version_range:
            return True

        purl_version = SemverVersion(self.purl.version)
        return purl_version in affected_package.affected_version_range

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

        if hasattr(self, "temp_dir") and os.path.exists(self.temp_dir):
            import shutil

            self.log(f"Removing temporary directory")
            shutil.rmtree(self.temp_dir)

    def on_failure(self):
        self.clean_downloads()
