#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timezone
from pathlib import Path
from traceback import format_exc as traceback_format_exc
from typing import Iterable

import pytz
from dateutil.parser import parse
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.utils import load_json


class PhotonOSImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect advisories from Photon OS OSV advisory feed.

    The upstream source is https://github.com/vmware/photon/wiki/Security-Advisories
    republished in OSV format at https://github.com/captn3m0/photon-os-advisories
    enriched using https://packages.vmware.com/photon/photon_cve_metadata/

    Sample advisory:
    {
        "affected": [
            {
                "package": {
                    "ecosystem": "Photon OS:4.0",
                    "name": "linux",
                    "purl": "pkg:rpm/vmware/linux?distro=photon-4"
                },
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "5.10.224-4.ph4"}
                        ],
                        "type": "ECOSYSTEM"
                    }
                ]
            }
        ],
        "id": "PHSA-2024-4.0-0685",
        "modified": "2025-01-24T05:27:06Z",
        "published": "2024-09-06T00:00:00Z",
        "references": [
            {
                "type": "ADVISORY",
                "url": "https://github.com/vmware/photon/wiki/Security-Update-4.0-685"
            }
        ],
        "related": ["CVE-2024-43853", "CVE-2024-43835", "CVE-2024-43854"]
    }
    """

    pipeline_id = "photon_os_importer"

    repo_url = "git+https://github.com/captn3m0/photon-os-advisories"
    spdx_license_expression = "CC-BY-SA-4.0"
    license_url = "https://github.com/vmware/photon/wiki/Security-Advisories"
    importer_name = "Photon OS Importer"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self) -> int:
        base_path = Path(self.vcs_response.dest_dir) / "advisories"
        return sum(1 for _ in base_path.rglob("*.json"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_path = Path(self.vcs_response.dest_dir) / "advisories"
        for file_path in base_path.glob("*.json"):
            advisory = parse_photon_advisory(file_path=file_path, logger=self.log)
            if advisory:
                yield advisory

    def clean_downloads(self):
        if hasattr(self, "vcs_response") and self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def normalize_ranges(ranges):
    """
    Return ranges as a list regardless of whether the input is a list or dict.

    The Photon OS OSV data is inconsistent — some entries have ``ranges``
    as a dict (invalid OSV) and others have it as a list (correct OSV).
    This function normalizes both formats to a list.
    """
    if not ranges:
        return []
    if isinstance(ranges, dict):
        return [ranges]
    if isinstance(ranges, list):
        return ranges
    return []


def extract_fixed_version(events, purl, file_path, logger=None):
    """
    Return a parsed fixed version object from an OSV events list, or None.

    Looks for a ``fixed`` key in the events and parses it using the
    version class appropriate for the purl type.

    For example::

    >>> purl = PackageURL.from_string("pkg:rpm/vmware/linux?distro=photon-4")
    >>> result = extract_fixed_version(
    ...     [{"introduced": "0"}, {"fixed": "5.10.224-4.ph4"}],
    ...     purl,
    ...     Path("/tmp/test.json"),
    ... )
    >>> str(result)
    '5.10.224-4.ph4'
    """
    fixed_str = None
    for event in events:
        if "fixed" in event:
            fixed_str = event["fixed"]
            break

    if not fixed_str:
        return None

    vrc = RANGE_CLASS_BY_SCHEMES.get(purl.type)
    if not vrc:
        if logger:
            logger(
                f"No version range class found for purl type {purl.type!r} in {file_path!r}",
                level=logging.ERROR,
            )
        return None

    try:
        return vrc.version_class(fixed_str)
    except Exception as e:
        if logger:
            logger(
                f"Failed to parse fixed version {fixed_str!r} "
                f"for {str(purl)!r} in {file_path!r}: {e!r}",
                level=logging.ERROR,
            )
        return None


def parse_affected_packages(affected_list, file_path, logger=None):
    """
    Return a deduplicated list of AffectedPackage objects.

    The Photon OS data contains duplicate package entries — the same purl
    appears multiple times, sometimes without ranges and sometimes with
    ranges in inconsistent formats (dict vs list). This function:

    1. Normalizes ranges from dict or list format to list
    2. Deduplicates by (purl_string, fixed_version_string)
    3. Only allows Entries with version data

    """
    # Key: (purl_string, fixed_version_string) → AffectedPackage
    # This deduplicates same package + same fixed version
    seen = {}

    for affected in affected_list or []:
        pkg_data = affected.get("package") or {}
        purl_str = pkg_data.get("purl")

        if not purl_str:
            if logger:
                logger(
                    f"Missing purl in {file_path!r} for package {pkg_data!r}",
                    level=logging.ERROR,
                )
            continue

        try:
            purl = PackageURL.from_string(purl_str)
        except Exception as e:
            if logger:
                logger(
                    f"Invalid purl {purl_str!r} in {file_path!r}: {e!r}",
                    level=logging.ERROR,
                )
            continue

        # Normalize ranges — handles both dict and list formats
        ranges = normalize_ranges(affected.get("ranges"))

        fixed_version = None
        for version_range in ranges:
            if version_range.get("type") != "ECOSYSTEM":
                continue
            events = version_range.get("events") or []
            fixed_version = extract_fixed_version(
                events=events,
                purl=purl,
                file_path=file_path,
                logger=logger,
            )
            if fixed_version:
                break

        if fixed_version is None:
            continue

        dedup_key = (str(purl), str(fixed_version))
        if dedup_key not in seen:
            seen[dedup_key] = AffectedPackage(
                package=purl,
                fixed_version=fixed_version,
            )

    return list(seen.values())

def parse_photon_advisory(file_path: Path, logger=None):
    """
    Parse a single Photon OS OSV advisory JSON file and return an AdvisoryData.

    Returns None if the file cannot be parsed or has unexpected format.
    """
    try:
        data = load_json(file_path)
    except Exception as e:
        if logger:
            logger(
                f"Failed to load JSON from {file_path!r}: {e!r}\n{traceback_format_exc()}",
                level=logging.ERROR,
            )
        return None

    if not isinstance(data, dict):
        if logger:
            logger(
                f"Unexpected format in {file_path!r}: expected dict, got {type(data)}",
                level=logging.ERROR,
            )
        return None

    # PHSA ID is the only alias — it is unique per OS version per patch batch
    # CVEs are shared across multiple OS versions and cause alias conflicts
    # when the same CVE is fixed in Photon 4.0, 5.0 etc. in separate advisories
    phsa_id = data.get("id")
    related_cves = data.get("related") or []
    aliases = [phsa_id] if phsa_id else []

    # Parse published date
    date_published = None
    published_raw = data.get("published")
    if published_raw:
        try:
            date_published = parse(published_raw).replace(tzinfo=pytz.UTC)
        except Exception as e:
            if logger:
                logger(
                    f"Failed to parse date {published_raw!r} in {file_path!r}: {e!r}",
                    level=logging.ERROR,
                )

    # Parse references from the advisory — first URL becomes the advisory URL
    references = []
    advisory_url = None
    for ref in data.get("references") or []:
        url = ref.get("url")
        if url:
            references.append(Reference(url=url))
            if not advisory_url:
                advisory_url = url

    # Add CVEs as references so the data is not lost
    # CVEs go here instead of aliases to avoid cross-advisory conflicts
    for cve_id in related_cves:
        references.append(
            Reference(
                url=f"https://www.cve.org/CVERecord?id={cve_id}",
                reference_id=cve_id,
            )
        )

    # Parse affected packages with deduplication
    affected_packages = parse_affected_packages(
        affected_list=data.get("affected"),
        file_path=file_path,
        logger=logger,
    )

    return AdvisoryData(
        aliases=aliases,
        affected_packages=affected_packages,
        references=references,
        date_published=date_published,
        url=advisory_url or "",
    )