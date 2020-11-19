# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import asyncio
from itertools import chain
import re
from typing import Optional, Mapping
from typing import Set
from typing import Tuple
from urllib.error import HTTPError
from urllib.request import urlopen

from dephell_specifier import RangeSpecifier
from packageurl import PackageURL
import toml

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import CratesVersionAPI
from vulnerabilities.helpers import load_toml


class RustDataSource(GitDataSource):
    def __enter__(self):
        super(RustDataSource, self).__enter__()

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

    def added_advisories(self) -> Set[Advisory]:
        return self._load_advisories(self._added_files)

    def updated_advisories(self) -> Set[Advisory]:
        return self._load_advisories(self._updated_files)

    def _load_advisories(self, files) -> Set[Advisory]:
        # per @tarcieri It will always be named RUSTSEC-0000-0000.md
        # https://github.com/nexB/vulnerablecode/pull/281/files#r528899864
        files = [f for f in files if not f.endswith("-0000.md")]  # skip temporary files
        packages = self.collect_packages(files)
        self.set_api(packages)

        while files:
            batch, files = files[: self.batch_size], files[self.batch_size:]
            advisories = set()
            for path in batch:
                advisory = self._load_advisory(path)
                if advisory:
                    advisories.add(advisory)
            yield advisories

    def collect_packages(self, paths):
        packages = set()
        for path in paths:
            record = get_advisory_data(path)
            packages.add(record["advisory"]["package"])

        return packages

    def _load_advisory(self, path: str) -> Optional[Advisory]:
        record = get_advisory_data(path)
        advisory = record.get("advisory", {})
        crate_name = advisory["package"]
        references = []
        if advisory.get("url"):
            references.append(Reference(url=advisory["url"]))

        all_versions = self.crates_api.get(crate_name)

        affected_ranges = {
            RangeSpecifier(r)
            for r in chain.from_iterable(record.get("affected", {}).get("functions", {}).values())
        }

        unaffected_ranges = {
            RangeSpecifier(r) for r in record.get("versions", {}).get("unaffected", [])
        }
        resolved_ranges = {RangeSpecifier(r) for r in record.get("versions", {}).get("patched", [])}

        unaffected, affected = categorize_versions(
            all_versions, unaffected_ranges, affected_ranges, resolved_ranges
        )

        impacted_purls = {PackageURL(type="cargo", name=crate_name, version=v) for v in affected}
        resolved_purls = {PackageURL(type="cargo", name=crate_name, version=v) for v in unaffected}

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

        return Advisory(
            summary=advisory.get("description", ""),
            impacted_package_urls=impacted_purls,
            resolved_package_urls=resolved_purls,
            cve_id=cve_id,
            vuln_references=references,
        )


def categorize_versions(
    all_versions: Set[str],
    unaffected_versions: Set[RangeSpecifier],
    affected_versions: Set[RangeSpecifier],
    resolved_versions: Set[RangeSpecifier],
) -> Tuple[Set[str], Set[str]]:
    """
    Categorize all versions of a crate according to the given version ranges.

    :return: unaffected versions, affected versions
    """
    unaffected, affected = set(), set()

    if not any(unaffected_versions.union(affected_versions).union(resolved_versions)):
        return unaffected, affected

    for version in all_versions:
        if affected_versions and all([version in av for av in affected_versions]):
            affected.add(version)
        elif unaffected_versions and all([version in av for av in unaffected_versions]):
            unaffected.add(version)
        elif resolved_versions and all([version in av for av in resolved_versions]):
            unaffected.add(version)

    # If some versions were not classified above, one or more of the given ranges might be empty, so
    # the remaining versions default to either affected or unaffected.
    uncategorized_versions = all_versions - unaffected.union(affected)
    if uncategorized_versions:
        if not affected_versions:
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
