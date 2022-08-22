#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from itertools import chain
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import pytz
import toml
from dateutil.parser import parse
from packageurl import PackageURL
from univers.version_range import CargoVersionRange
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.package_managers import CratesVersionAPI
from vulnerabilities.package_managers import PackageVersion
from vulnerabilities.utils import nearest_patched_package

logger = logging.getLogger(__name__)


class RustImporter(GitImporter):
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/rustsec/advisory-db/blob/main/LICENSE.txt"

    def __init__(self):
        super().__init__(repo_url="git+https://github.com/rustsec/advisory-db")
        self.pkg_manager_api = CratesVersionAPI()

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone()
            path = Path(self.vcs_response.dest_dir)
            glob = "crates/**/*.md"
            files = (p for p in path.glob(glob) if p.is_file())
            for file in files:
                # per @tarcieri It will always be named RUSTSEC-0000-0000.md
                # https://github.com/nexB/vulnerablecode/pull/281/files#r528899864
                if not file.stem.endswith("-0000"):  # skip temporary files
                    # packages = collect_packages(files)
                    yield self.parse_rust_advisory(str(file))
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def parse_rust_advisory(self, path: str) -> Optional[AdvisoryData]:
        record = get_advisory_data(path)
        advisory = record.get("advisory", {})
        crate_name = advisory["package"]
        references = []
        if advisory.get("url"):
            references.append(Reference(url=advisory["url"]))

        publish_date = parse(advisory["date"]).replace(tzinfo=pytz.UTC)
        all_versions = self.pkg_manager_api.fetch(crate_name)

        # FIXME: Avoid wildcard version ranges for now.
        # See https://github.com/RustSec/advisory-db/discussions/831
        # affected_ranges = [
        #     CargoVersionRange.from_natives(r)
        #     for r in chain.from_iterable(record.get("affected", {}).get("functions", {}).values())
        #     if r != "*"
        # ]
        #
        # unaffected_ranges = [
        #     CargoVersionRange.from_natives(r)
        #     for r in record.get("versions", {}).get("unaffected", [])
        #     if r != "*"
        # ]
        # resolved_ranges = [
        #     CargoVersionRange.from_natives(r)
        #     for r in record.get("versions", {}).get("patched", [])
        #     if r != "*"
        # ]
        #
        # unaffected, affected = categorize_versions(
        #     all_versions, unaffected_ranges, affected_ranges, resolved_ranges
        # )

        # impacted_purls = [PackageURL(type="cargo", name=crate_name, version=v) for v in affected]
        # resolved_purls = [PackageURL(type="cargo", name=crate_name, version=v) for v in unaffected]

        aliases = advisory.get("aliases") or []
        aliases.append(advisory.get("id"))

        references.append(
            Reference(
                reference_id=advisory["id"],
                url="https://rustsec.org/advisories/{}.html".format(advisory["id"]),
            )
        )

        x = AdvisoryData(
            aliases=aliases,
            summary=advisory.get("description") or "",
            #   affected_packages=nearest_patched_package(impacted_purls, resolved_purls),
            references=references,
        )
        return x


def categorize_versions(
    all_versions: Iterable[PackageVersion],
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
        version_obj = SemverVersion(version.value)
        if affected_version_ranges and all([version_obj in av for av in affected_version_ranges]):
            affected.add(version.value)
        elif unaffected_version_ranges and all(
            [version_obj in av for av in unaffected_version_ranges]
        ):
            unaffected.add(version.value)
        elif resolved_version_ranges and all([version_obj in av for av in resolved_version_ranges]):
            unaffected.add(version.value)

    # If some versions were not classified above, one or more of the given ranges might be empty, so
    # the remaining versions default to either affected or unaffected.
    uncategorized_versions = [i.value for i in all_versions] - unaffected.union(affected)
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


def collect_packages(paths):
    packages = set()
    for path in paths:
        record = get_advisory_data(path)
        packages.add(record["advisory"]["package"])
    return packages
