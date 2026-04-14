#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from dataclasses import dataclass
from datetime import datetime
from datetime import timezone as dt_timezone

import pytest
from packageurl import PackageURL

from vulnerabilities.improvers.valid_versions import DebianBasicImprover
from vulnerabilities.models import Package
from vulnerabilities.models import PackageV2


@dataclass
class MockVersion:
    value: str
    release_date: datetime | None


@pytest.mark.django_db
def test_get_package_versions_stores_release_date(monkeypatch):
    package = Package.objects.create(type="pypi", name="demo", version="1.0.0")
    package_v2 = PackageV2.objects.create(type="pypi", name="demo", version="1.0.0")

    release_date = datetime(2024, 1, 15, tzinfo=dt_timezone.utc)
    mock_versions = [
        MockVersion(value="1.0.0", release_date=release_date),
        MockVersion(value="2.0.0", release_date=None),
    ]

    monkeypatch.setattr(
        "vulnerabilities.improvers.valid_versions.package_versions.versions",
        lambda *_args, **_kwargs: mock_versions,
    )

    purl = PackageURL(type="pypi", name="demo")
    versions = DebianBasicImprover().get_package_versions(package_url=purl)

    assert versions == ["1.0.0", "2.0.0"]

    package.refresh_from_db()
    package_v2.refresh_from_db()
    assert package.release_date == release_date
    assert package_v2.release_date == release_date
