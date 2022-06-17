#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import asyncio
from itertools import chain
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import pytz
import toml
from dateutil.parser import parse
from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.package_managers import CratesVersionAPI
from vulnerabilities.utils import nearest_patched_package


class RustImporter(GitImporter):
    def __enter__(self):
        super(RustImporter, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                subdir="crates",  # TODO Consider importing the advisories for cargo, etc as well.
                recursive=True,
                file_ext="md",
            )

    @property
    def crates_api(self):
        if not hasattr(self, "_crates_api"):
            setattr(self, "_crates_api", CratesVersionAPI())
        return self._crates_api

    def set_api(self, packages):
        asyncio.run(self.crates_api.load_api(packages))

    def updated_advisories(self) -> Set[AdvisoryData]:
        return self._load_advisories(self._updated_files.union(self._added_files))

    def _load_advisories(self, files) -> Set[AdvisoryData]:
        # per @tarcieri It will always be named RUSTSEC-0000-0000.md
        # https://github.com/nexB/vulnerablecode/pull/281/files#r528899864
        files = [f for f in files if not f.endswith("-0000.md")]  # skip temporary files
        packages = self.collect_packages(files)
        self.set_api(packages)

        while files:
            batch, files = files[: self.batch_size], files[self.batch_size :]
            advisories = []
            for path in batch:
                advisory = self._load_advisory(path)
                if advisory:
                    advisories.append(advisory)
            yield advisories

    def collect_packages(self, paths):
        packages = set()
        for path in paths:
            record = get_advisory_data(path)
            packages.add(record["advisory"]["package"])

        return packages

    def _load_advisory(self, path: str) -> Optional[AdvisoryData]:
        record = get_advisory_data(path)
        advisory = record.get("advisory", {})
        crate_name = advisory["package"]
        references = []
        if advisory.get("url"):
            references.append(Reference(url=advisory["url"]))

        publish_date = parse(advisory["date"]).replace(tzinfo=pytz.UTC)
        all_versions = self.crates_api.get(crate_name, publish_date).valid_versions

        # FIXME: Avoid wildcard version ranges for now.
        # See https://github.com/RustSec/advisory-db/discussions/831
        affected_ranges = [
            VersionRange.from_scheme_version_spec_string("semver", r)
            for r in chain.from_iterable(record.get("affected", {}).get("functions", {}).values())
            if r != "*"
        ]

        unaffected_ranges = [
            VersionRange.from_scheme_version_spec_string("semver", r)
            for r in record.get("versions", {}).get("unaffected", [])
            if r != "*"
        ]
        resolved_ranges = [
            VersionRange.from_scheme_version_spec_string("semver", r)
            for r in record.get("versions", {}).get("patched", [])
            if r != "*"
        ]

        unaffected, affected = categorize_versions(
            all_versions, unaffected_ranges, affected_ranges, resolved_ranges
        )

        impacted_purls = [PackageURL(type="cargo", name=crate_name, version=v) for v in affected]
        resolved_purls = [PackageURL(type="cargo", name=crate_name, version=v) for v in unaffected]

        cve_id = None
        if "aliases" in advisory:
            for alias in advisory["aliases"]:
                if alias.startswith("CVE-"):
                    cve_id = alias
                    break

        references.append(
            Reference(
                reference_id=advisory["id"],
                url="https://rustsec.org/advisories/{}.html".format(advisory["id"]),
            )
        )

        return AdvisoryData(
            summary=advisory.get("description", ""),
            affected_packages=nearest_patched_package(impacted_purls, resolved_purls),
            vulnerability_id=cve_id,
            references=references,
        )


def categorize_versions(
    all_versions: Set[str],
    unaffected_version_ranges: List[VersionRange],
    affected_version_ranges: List[VersionRange],
    resolved_version_ranges: List[VersionRange],
) -> Tuple[Set[str], Set[str]]:
    """
    Categorize all versions of a crate according to the given version ranges.

    :return: unaffected versions, affected versions
    """

    unaffected, affected = set(), set()

    if (
        not unaffected_version_ranges
        and not affected_version_ranges
        and not resolved_version_ranges
    ):
        return unaffected, affected

    # TODO: This is probably wrong
    for version in all_versions:
        version_obj = SemverVersion(version)
        if affected_version_ranges and all([version_obj in av for av in affected_version_ranges]):
            affected.add(version)
        elif unaffected_version_ranges and all(
            [version_obj in av for av in unaffected_version_ranges]
        ):
            unaffected.add(version)
        elif resolved_version_ranges and all([version_obj in av for av in resolved_version_ranges]):
            unaffected.add(version)

    # If some versions were not classified above, one or more of the given ranges might be empty, so
    # the remaining versions default to either affected or unaffected.
    uncategorized_versions = all_versions - unaffected.union(affected)
    if uncategorized_versions:
        if not affected_version_ranges:
            affected.update(uncategorized_versions)
        else:
            unaffected.update(uncategorized_versions)

    return unaffected, affected


def get_toml_lines(lines):
    """
    Yield lines of TOML extracted from an iterable of text ``lines``.
    The lines are expected to be from a RustSec Markdown advisory file with
    embedded TOML metadata.

    For example::

    >>> text = '''
    ... ```toml
    ... [advisory]
    ... id = "RUST-001"
    ...
    ... [versions]
    ... patch = [">= 1.2.1"]
    ... ```
    ... # Use-after-free with objects returned by `Stream`'s `get_format_info`
    ...
    ... Affected versions contained a pair of use-after-free issues with the objects.
    ... '''
    >>> list(get_toml_lines(text.splitlines()))
    ['', '[advisory]', 'id = "RUST-001"', '', '[versions]', 'patch = [">= 1.2.1"]']
    """

    for line in lines:
        line = line.strip()
        if line.startswith("```toml"):
            continue
        elif line.endswith("```"):
            break
        else:
            yield line


def data_from_toml_lines(lines):
    """
    Return a mapping of data from an iterable of TOML text ``lines``.

    For example::

    >>> lines = ['[advisory]', 'id = "RUST1"', '', '[versions]', 'patch = [">= 1"]']
    >>> data_from_toml_lines(lines)
    {'advisory': {'id': 'RUST1'}, 'versions': {'patch': ['>= 1']}}
    """
    return toml.loads("\n".join(lines))


def get_advisory_data(location):
    """
    Return a mapping of vulnerability data from a RustSec advisory file at
    ``location``.
    RustSec advisories documents are .md files starting with a block of TOML
    identified as the text inside a tripple-backtick TOML block. Per
    https://github.com/RustSec/advisory-db#advisory-format:
        Advisories are formatted in Markdown with TOML "front matter".
    """

    with open(location) as lines:
        toml_lines = get_toml_lines(lines)
        return data_from_toml_lines(toml_lines)
