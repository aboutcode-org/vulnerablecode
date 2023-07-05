#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import GemVersionRange
from univers.versions import RubygemsVersion

from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import NoAffectedPackages
from vulnerabilities.importer import UnMergeablePackageError


def test_affected_package_merge_fail():
    with pytest.raises(UnMergeablePackageError):
        AffectedPackage.merge(
            [
                AffectedPackage(
                    package=PackageURL(type="gem", name="foo"),
                    fixed_version=RubygemsVersion(string="5.2.8.1"),
                    affected_version_range=GemVersionRange(
                        constraints=(
                            VersionConstraint(
                                comparator=">=", version=RubygemsVersion(string="5.2.0")
                            ),
                            VersionConstraint(
                                comparator="<=", version=RubygemsVersion(string="5.2.6.2")
                            ),
                        )
                    ),
                ),
                AffectedPackage(package=PackageURL(type="npm", name="bar"), fixed_version="1.0.0"),
            ]
        )


def test_affected_package_merge():
    result = AffectedPackage.merge(
        [
            AffectedPackage(
                package=PackageURL(type="npm", name="foo"),
                fixed_version="1.0.0",
                affected_version_range=GemVersionRange(
                    constraints=(
                        VersionConstraint(comparator=">=", version=RubygemsVersion(string="5.2.0")),
                        VersionConstraint(
                            comparator="<=", version=RubygemsVersion(string="5.2.6.2")
                        ),
                    )
                ),
            ),
            AffectedPackage(package=PackageURL(type="npm", name="foo"), fixed_version="2.0.0"),
            AffectedPackage(
                package=PackageURL(type="npm", name="foo"),
                affected_version_range=GemVersionRange(
                    constraints=(
                        VersionConstraint(
                            comparator=">=", version=RubygemsVersion(string="10.2.0")
                        ),
                        VersionConstraint(
                            comparator="<=", version=RubygemsVersion(string="10.5.0")
                        ),
                    )
                ),
            ),
        ]
    )
    expected = (
        PackageURL(
            type="npm", namespace=None, name="foo", version=None, qualifiers={}, subpath=None
        ),
        [
            GemVersionRange(
                constraints=(
                    VersionConstraint(comparator=">=", version=RubygemsVersion(string="5.2.0")),
                    VersionConstraint(comparator="<=", version=RubygemsVersion(string="5.2.6.2")),
                )
            ),
            GemVersionRange(
                constraints=(
                    VersionConstraint(comparator=">=", version=RubygemsVersion(string="10.2.0")),
                    VersionConstraint(comparator="<=", version=RubygemsVersion(string="10.5.0")),
                )
            ),
        ],
        ["1.0.0", "2.0.0"],
    )
    assert expected == result


def test_affected_package_merge_empty_list():
    with pytest.raises(NoAffectedPackages):
        AffectedPackage.merge([])
