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
from pathlib import Path
from typing import Iterable

from dateutil.parser import parse
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from pytz import UTC
from univers.gem import InvalidRequirementError
from univers.version_constraint import VersionConstraint
from univers.version_constraint import validate_comparators
from univers.version_range import GemVersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import CVSSV2
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import CVSSV4
from vulnerabilities.utils import build_description
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import load_yaml

logger = logging.getLogger(__name__)


class RubyImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    license_url = "https://github.com/rubysec/ruby-advisory-db/blob/master/LICENSE.txt"
    repo_url = "git+https://github.com/rubysec/ruby-advisory-db"
    importer_name = "Ruby Importer"
    pipeline_id = "ruby_importer_v2"
    datasource_id = "ruby_advisory_db"
    spdx_license_expression = "LicenseRef-scancode-public-domain-disclaimer"
    notice = """
    If you submit code or data to the ruby-advisory-db that is copyrighted by
    yourself, upon submission you hereby agree to release it into the public
    domain.

    The data imported from the ruby-advisory-db have been filtered to exclude 
    any non-public domain data from the data copyrighted by the Open 
    Source Vulnerability Database (http://osvdb.org).

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
    """

    precedence = 500

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
        base_path = Path(self.vcs_response.dest_dir)
        return sum(1 for _ in base_path.rglob("*.yml"))

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        base_path = Path(self.vcs_response.dest_dir)
        for file_path in base_path.rglob("*.yml"):
            if file_path.name.startswith("OSVDB-"):
                continue

            if "gems" in file_path.parts:
                subdir = "gems"
            elif "rubies" in file_path.parts:
                subdir = "rubies"
            else:
                continue

            raw_data = load_yaml(file_path)
            advisory_id = str(file_path.relative_to(base_path).with_suffix(""))
            advisory_url = get_advisory_url(
                file=file_path,
                base_path=base_path,
                url="https://github.com/rubysec/ruby-advisory-db/blob/master/",
            )
            yield parse_ruby_advisory(advisory_id, raw_data, subdir, advisory_url)

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def parse_ruby_advisory(advisory_id, record, schema_type, advisory_url):
    """
    Parse a ruby advisory file and return an AdvisoryDataV2 or None.
    Each advisory file contains the advisory information in YAML format.
    Schema: https://github.com/rubysec/ruby-advisory-db/tree/master/spec/schemas
    """
    if schema_type == "gems":
        package_name = record.get("gem")

        if not package_name:
            logger.error("Invalid package name")
            return

        purl = PackageURL(type="gem", name=package_name)
        return AdvisoryDataV2(
            advisory_id=advisory_id,
            aliases=get_aliases(record),
            summary=get_summary(record),
            affected_packages=get_affected_packages(record, purl),
            references=get_references(record),
            severities=get_severities(record),
            date_published=get_publish_time(record),
            url=advisory_url,
            original_advisory_text=json.dumps(record, indent=2, ensure_ascii=False),
        )

    elif schema_type == "rubies":
        engine = record.get("engine")  # engine enum: [jruby, rbx, ruby]
        if not engine:
            logger.error("Invalid engine name")
            return

        purl = PackageURL(type="ruby", name=engine)
        return AdvisoryDataV2(
            advisory_id=advisory_id,
            aliases=get_aliases(record),
            summary=get_summary(record),
            affected_packages=get_affected_packages(record, purl),
            severities=get_severities(record),
            references=get_references(record),
            date_published=get_publish_time(record),
            url=advisory_url,
            original_advisory_text=json.dumps(record, indent=2, ensure_ascii=False),
        )


def _is_nonempty_interval(lower, upper):
    if lower is None or upper is None:
        return True
    lower_ver, lower_inc = lower
    upper_ver, upper_inc = upper
    return lower_ver < upper_ver or (lower_ver == upper_ver and lower_inc and upper_inc)


def _compare_bounds(a, b, pick_larger, combine_inclusive):
    a_ver, a_inc = a
    b_ver, b_inc = b
    if a_ver != b_ver:
        return a if (a_ver > b_ver) == pick_larger else b
    return (a_ver, combine_inclusive(a_inc, b_inc))


def _merge_intervals(intervals):
    """Return a sorted list of disjoint, merged (lower, upper) version intervals."""
    if not intervals:
        return []

    def sort_key(interval):
        lower = interval[0]
        if lower is None:
            return (0, None, 0)
        return (1, lower[0], 0 if lower[1] else 1)

    sorted_intervals = sorted(intervals, key=sort_key)
    merged = [sorted_intervals[0]]
    for lower, upper in sorted_intervals[1:]:
        prev_lower, prev_upper = merged[-1]
        if prev_upper is None:
            continue
        if lower is None:
            overlaps_or_touches = True
        else:
            prev_ver, prev_inc = prev_upper
            cur_ver, cur_inc = lower
            overlaps_or_touches = cur_ver < prev_ver or (
                cur_ver == prev_ver and (prev_inc or cur_inc)
            )
        if overlaps_or_touches:
            if upper is None:
                next_upper = None
            else:
                next_upper = _compare_bounds(
                    prev_upper, upper, pick_larger=True, combine_inclusive=lambda x, y: x or y
                )
            merged[-1] = (prev_lower, next_upper)
        else:
            merged.append((lower, upper))
    return merged


def _intersect_interval_lists(left, right):
    """Return the intersection of two interval lists as merged disjoint intervals."""
    intersected = []
    for left_lower, left_upper in left:
        for right_lower, right_upper in right:
            if left_lower is None:
                lower = right_lower
            elif right_lower is None:
                lower = left_lower
            else:
                lower = _compare_bounds(
                    left_lower,
                    right_lower,
                    pick_larger=True,
                    combine_inclusive=lambda x, y: x and y,
                )

            if left_upper is None:
                upper = right_upper
            elif right_upper is None:
                upper = left_upper
            else:
                upper = _compare_bounds(
                    left_upper,
                    right_upper,
                    pick_larger=False,
                    combine_inclusive=lambda x, y: x and y,
                )

            if _is_nonempty_interval(lower, upper):
                intersected.append((lower, upper))
    return _merge_intervals(intersected)


def _range_to_intervals(version_range):
    """Convert a GemVersionRange into sorted disjoint (lower, upper) intervals."""
    intervals = [(None, None)]
    for constraint in version_range.constraints:
        ver = constraint.version
        comp = constraint.comparator
        if comp == "*":
            constraint_intervals = [(None, None)]
        elif comp == "=":
            constraint_intervals = [((ver, True), (ver, True))]
        elif comp == ">=":
            constraint_intervals = [((ver, True), None)]
        elif comp == ">":
            constraint_intervals = [((ver, False), None)]
        elif comp == "<=":
            constraint_intervals = [(None, (ver, True))]
        elif comp == "<":
            constraint_intervals = [(None, (ver, False))]
        elif comp == "!=":
            constraint_intervals = [(None, (ver, False)), ((ver, False), None)]
        else:
            raise ValueError(f"Unsupported comparator: {comp}")
        intervals = _intersect_interval_lists(intervals, constraint_intervals)
    return intervals


def _complement_intervals(intervals):
    """Return the complement of a sorted disjoint interval list."""
    if not intervals:
        return [(None, None)]

    complement = []
    first_lower, _ = intervals[0]
    if first_lower is not None:
        ver, inc = first_lower
        complement.append((None, (ver, not inc)))

    for (_, prev_upper), (next_lower, _) in zip(intervals, intervals[1:]):
        prev_ver, prev_inc = prev_upper
        next_ver, next_inc = next_lower
        lower = (prev_ver, not prev_inc)
        upper = (next_ver, not next_inc)
        if _is_nonempty_interval(lower, upper):
            complement.append((lower, upper))

    _, last_upper = intervals[-1]
    if last_upper is not None:
        ver, inc = last_upper
        complement.append(((ver, not inc), None))

    return complement


def _intervals_to_gem_range(intervals):
    """Convert a sorted disjoint interval list into a canonical GemVersionRange."""
    if not intervals:
        return None

    constraints = []
    idx = 0
    while idx < len(intervals):
        lower, upper = intervals[idx]
        if (
            lower is not None
            and upper is not None
            and lower[0] == upper[0]
            and lower[1]
            and upper[1]
        ):
            constraints.append(VersionConstraint(comparator="=", version=lower[0]))
            idx += 1
            continue

        if lower is not None:
            constraints.append(
                VersionConstraint(comparator=">=" if lower[1] else ">", version=lower[0])
            )

        # Collapse adjacent open gaps around a single excluded version into !=v
        # so versions remain unique in the resulting vers constraints.
        while (
            upper is not None
            and not upper[1]
            and idx + 1 < len(intervals)
            and intervals[idx + 1][0] is not None
            and not intervals[idx + 1][0][1]
            and upper[0] == intervals[idx + 1][0][0]
        ):
            constraints.append(VersionConstraint(comparator="!=", version=upper[0]))
            idx += 1
            upper = intervals[idx][1]

        if upper is not None:
            constraints.append(
                VersionConstraint(comparator="<=" if upper[1] else "<", version=upper[0])
            )
        idx += 1

    if not constraints:
        return None
    return GemVersionRange(constraints=constraints)


def invert_unaffected_versions(unaffected_versions):
    """
    Combine all entries from ``unaffected_versions`` as a union of safe ranges
    and return their inverted affected ``GemVersionRange``, or None if empty.
    """
    has_valid_entry = False
    unaffected_intervals = []
    for unaffected_version in unaffected_versions or []:
        if not unaffected_version or not unaffected_version.strip():
            continue
        unaffected_version = unaffected_version.strip()
        try:
            unaffected_range = GemVersionRange.from_native(unaffected_version)
            validate_comparators(unaffected_range.constraints)
            has_valid_entry = True
            unaffected_intervals.extend(_range_to_intervals(unaffected_range))
        except (ValueError, InvalidRequirementError) as e:
            logger.error(
                f"Invalid VersionRange Constraints for unaffected_version: "
                f"{unaffected_version} - error: {e}"
            )

    if not has_valid_entry:
        return None

    affected_intervals = _complement_intervals(_merge_intervals(unaffected_intervals))
    if affected_intervals == [(None, None)]:
        return GemVersionRange.from_string("vers:gem/*")

    affected_version_range = _intervals_to_gem_range(affected_intervals)
    if affected_version_range is not None:
        validate_comparators(affected_version_range.constraints)
    return affected_version_range


def get_affected_packages(record, purl):
    """
    Return AffectedPackageV2 objects for ``record``, combining ``unaffected_versions``
    into a single inverted ``affected_version_range`` and converting ``patched_versions``
    into ``fixed_version_range`` entries.
    """
    affected_packages = []
    affected_version_range = invert_unaffected_versions(record.get("unaffected_versions"))
    if affected_version_range:
        affected_packages.append(
            AffectedPackageV2(
                package=purl,
                affected_version_range=affected_version_range,
                fixed_version_range=None,
            )
        )

    for patched_version in record.get("patched_versions") or []:
        if not patched_version or not patched_version.strip():
            continue
        try:
            fixed_version_range = GemVersionRange.from_native(patched_version.strip())
            validate_comparators(fixed_version_range.constraints)
            affected_packages.append(
                AffectedPackageV2(
                    package=purl,
                    affected_version_range=None,
                    fixed_version_range=fixed_version_range,
                )
            )
        except (ValueError, InvalidRequirementError) as e:
            logger.error(
                f"Invalid VersionRange Constraints for patched_version: "
                f"{patched_version} - error: {e}"
            )

    return affected_packages


def get_aliases(record) -> [str]:
    aliases = []
    if record.get("cve"):
        aliases.append("CVE-{}".format(record.get("cve")))
    if record.get("osvdb"):
        aliases.append("OSV-{}".format(record.get("osvdb")))
    if record.get("ghsa"):
        aliases.append("GHSA-{}".format(record.get("ghsa")))
    return aliases


def get_references(record) -> [ReferenceV2]:
    references = []
    if record.get("url"):
        references.append(
            ReferenceV2(
                url=record.get("url"),
            )
        )
    return references


def get_severities(record):
    """
    Extract CVSS severity and return a list of VulnerabilitySeverity objects
    """

    severities = []
    cvss_v4 = record.get("cvss_v4")
    if cvss_v4:
        severities.append(
            VulnerabilitySeverity(system=CVSSV4, value=cvss_v4),
        )

    cvss_v3 = record.get("cvss_v3")
    if cvss_v3:
        severities.append(VulnerabilitySeverity(system=CVSSV3, value=cvss_v3))

    cvss_v2 = record.get("cvss_v2")
    if cvss_v2:
        severities.append(VulnerabilitySeverity(system=CVSSV2, value=cvss_v2))

    return severities


def get_publish_time(record):
    date = record.get("date")
    if not date:
        return
    return parse(date).replace(tzinfo=UTC)


def get_summary(record):
    title = record.get("title") or ""
    description = record.get("description") or ""
    return build_description(summary=title, description=description)
