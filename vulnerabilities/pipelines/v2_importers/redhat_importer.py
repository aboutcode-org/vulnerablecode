#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import logging
import shutil
import tempfile
from io import DEFAULT_BUFFER_SIZE
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin

import dateparser
import requests
from extractcode import ExtractError
from packageurl import PackageURL
from univers.version_range import RpmVersionRange
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes import extractcode_utils
from vulnerabilities.severity_systems import REDHAT_AGGREGATE
from vulnerabilities.utils import load_json
from vulntotal import vulntotal_utils


class RedHatImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Import RedHat Advisories (RHSA, RHEA and RHBA)

    Ingest CSAF advisories published by RedHat, including Red Hat Security Advisory (RHSA),
    Red Hat Enhancement Advisory (RHEA), and Red Hat Bug Fix Advisory (RHBA).
    """

    pipeline_id = "redhat_importer_v2"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://access.redhat.com/security/data/"
    url = "https://security.access.redhat.com/data/csaf/v2/advisories/"

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
            cls.clean_download,
        )

    def fetch(self):
        archive_latest_url = urljoin(self.url, "archive_latest.txt")
        response = requests.get(archive_latest_url)
        response.raise_for_status()
        self.latest_archive_name = response.text.strip()

        self.location = self.cleanup_location = Path(tempfile.mkdtemp())
        archive_path = self.location / self.latest_archive_name
        archive_url = urljoin(self.url, self.latest_archive_name)

        response = requests.get(archive_url, stream=True)
        response.raise_for_status()

        with open(archive_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=DEFAULT_BUFFER_SIZE):
                f.write(chunk)

        if errors := extractcode_utils.extract_archive(
            source=archive_path,
            destination=self.location,
        ):
            self.log(
                f"Error while extracting archive {archive_path}: {errors}",
                level=logging.ERROR,
            )
            raise ExtractError(errors)

    def advisories_count(self) -> int:
        return sum(1 for _ in self.location.rglob("*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for record in self.location.rglob("*.json"):
            yield self.parse_advisory(record)

    def parse_advisory(self, record):
        advisory = load_json(record)
        document = advisory.get("document", {})
        if (csaf_version := document.get("csaf_version")) and not csaf_version == "2.0":
            self.log(f"Unsupported CSAF version: {csaf_version}.", level=logging.ERROR)
            return

        severities = []
        references = []
        impacts = []
        affected_packages = []
        notes = document.get("notes", [])
        adv_sub_path = f"{record.parent.name}/{record.name}"
        url = urljoin(self.url, adv_sub_path)
        advisory_id = get_item(document, "tracking", "id")
        release_date = get_item(document, "tracking", "initial_release_date")

        summary = "\n\n".join(
            note["text"] for note in notes if note["category"] != "legal_disclaimer"
        )
        aliases = [vul["cve"] for vul in advisory.get("vulnerabilities", [])]

        for ref in document.get("references", []):
            ref_url = ref.get("url")
            if ref_url.startswith("https://bugzilla.redhat.com/"):
                references.append(
                    ReferenceV2(
                        reference_id=ref.get("summary"),
                        reference_type="bug",
                        url=ref_url,
                    )
                )
                continue
            references.append(ReferenceV2.from_url(url=ref_url))

        if aggregate_severity := document.get("aggregate_severity"):
            severities.append(
                VulnerabilitySeverity(
                    system=REDHAT_AGGREGATE,
                    value=aggregate_severity["text"],
                    url=url,
                )
            )

        impacts = get_item(advisory, "product_tree", "branches", 0, "branches", default=[])
        for impact in impacts:
            if impact["category"] == "product_family":
                continue
            for branch in impact.get("branches", []):
                if purl := get_item(
                    branch,
                    "product",
                    "product_identification_helper",
                    "purl",
                    default=None,
                ):
                    if not purl.startswith("pkg:rpm/"):
                        continue
                    package_purl = PackageURL.from_string(purl=purl)
                    fixed_version = package_purl.version
                    if not fixed_version:
                        continue

                    fixed_version_range = RpmVersionRange.from_versions([fixed_version])
                    affected_version_range = VersionRange.from_string(f"vers:rpm/<{fixed_version}")
                    purl_dict = package_purl.to_dict()
                    del purl_dict["version"]
                    base_purl = PackageURL(**purl_dict)

                    affected_packages.append(
                        AffectedPackageV2(
                            package=base_purl,
                            affected_version_range=affected_version_range,
                            fixed_version_range=fixed_version_range,
                        )
                    )

        return AdvisoryDataV2(
            advisory_id=advisory_id,
            aliases=aliases,
            summary=summary,
            references=references,
            affected_packages=affected_packages,
            severities=severities,
            weaknesses=[],
            date_published=dateparser.parse(release_date) if release_date else None,
            url=url,
            original_advisory_text=json.dumps(advisory),
        )

    def clean_download(self):
        if hasattr(self, "cleanup_location") and self.cleanup_location.exists():
            self.log(f"Removing downloaded archive: {self.latest_archive_name}")
            shutil.rmtree(self.cleanup_location)

    def on_failure(self):
        self.clean_download()


def get_item(entity, *attributes, default=None):
    try:
        result = vulntotal_utils.get_item(entity, *attributes)
    except (KeyError, IndexError, TypeError) as e:
        result = default
    return result
