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
from typing import Iterable

from dateutil.parser import parse
from packageurl import PackageURL
from pytz import UTC
from univers.version_range import GemVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from fetchcode.vcs import fetch_via_vcs
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import build_description, get_advisory_url, load_yaml

logger = logging.getLogger(__name__)


class RubyImporterPipeline(VulnerableCodeBaseImporterPipelineV2):

    pipeline_id = "ruby_importer_v2"
    label = "Ruby"
    repo_url = "git+https://github.com/rubysec/ruby-advisory-db"
    license_url = "https://github.com/rubysec/ruby-advisory-db/blob/master/LICENSE.txt"
    spdx_license_expression = "LicenseRef-scancode-public-domain-disclaimer"
    importer_name = "Ruby Importer"

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)
    
    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self) -> int:
        base_path = Path(self.vcs_response.dest_dir)
        count = 0
        for subdir in ["rubies", "gems"]:
            count += len(list((base_path / subdir).glob("**/*.yml")))
        return count

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        try:
            base_path = Path(self.vcs_response.dest_dir)
            for subdir in ["rubies", "gems"]:
                for file_path in (base_path / subdir).glob("**/*.yml"):
                    if file_path.name.startswith("OSVDB-"):
                        continue
                    raw_data = load_yaml(file_path)
                    advisory_url = get_advisory_url(
                        file=file_path,
                        base_path=base_path,
                        url="https://github.com/rubysec/ruby-advisory-db/blob/master/",
                    )
                    advisory = self.parse_ruby_advisory(raw_data, subdir, advisory_url)
                    if advisory:
                        yield advisory
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def parse_ruby_advisory(self, record, schema_type, advisory_url) -> AdvisoryData:
        if schema_type == "gems":
            package_name = record.get("gem")
            if not package_name:
                logger.error("Invalid gem package name")
                return
            purl = PackageURL(type="gem", name=package_name)
        elif schema_type == "rubies":
            engine = record.get("engine")
            if not engine:
                logger.error("Invalid ruby engine name")
                return
            purl = PackageURL(type="ruby", name=engine)
        else:
            return

        return AdvisoryData(
            advisory_id=self.get_advisory_id(record),
            aliases=self.get_aliases(record),
            summary=self.get_summary(record),
            affected_packages=self.get_affected_packages(record, purl),
            references_v2=self.get_references(record),
            date_published=self.get_publish_time(record),
            url=advisory_url,
        )

    def get_advisory_id(self, record):
        cve = record.get("cve")
        if cve:
            return f"CVE-{cve}" if not cve.startswith("CVE-") else cve
        ghsa = record.get("ghsa")
        return f"GHSA-{ghsa}" if ghsa else None

    def get_aliases(self, record) -> list[str]:
        aliases = []
        if record.get("cve"):
            aliases.append("CVE-{}".format(record.get("cve")))
        if record.get("osvdb"):
            aliases.append("OSV-{}".format(record.get("osvdb")))
        if record.get("ghsa"):
            aliases.append("GHSA-{}".format(record.get("ghsa")))
        return aliases

    def get_affected_packages(self, record, purl) -> list[AffectedPackage]:
        safe_version_ranges = record.get("patched_versions", []) or []
        safe_version_ranges += record.get("unaffected_versions", []) or []
        safe_version_ranges = [r for r in safe_version_ranges if r]

        affected_packages = []
        for range_str in safe_version_ranges:
            affected_packages.append(
                AffectedPackage(
                    package=purl,
                    affected_version_range=GemVersionRange.from_native(range_str).invert(),
                )
            )
        return affected_packages

    def get_references(self, record) -> list[Reference]:
        references = []
        url = record.get("url")
        cvss_v3 = record.get("cvss_v3")
        if url:
            if not cvss_v3:
                references.append(Reference(url=url))
            else:
                references.append(
                    Reference(
                        url=url,
                        severities=[
                            VulnerabilitySeverity(system=SCORING_SYSTEMS["cvssv3"], value=cvss_v3)
                        ],
                    )
                )
        return references

    def get_publish_time(self, record):
        date = record.get("date")
        return parse(date).replace(tzinfo=UTC) if date else None

    def get_summary(self, record):
        return build_description(
            summary=record.get("title") or "",
            description=record.get("description") or "",
        )
