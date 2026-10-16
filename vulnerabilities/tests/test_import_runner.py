#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest
from django.utils import timezone
from univers.version_range import VersionRange

from vulnerabilities import models
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageURL
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2

ADVISORY_DATAS = [
    AdvisoryDataV2(
        aliases=["CVE-2020-13371337"],
        advisory_id="CVE-2020-1337137",
        summary="vulnerability description here",
        affected_packages=[
            AffectedPackageV2(
                package=PackageURL(type="pypi", name="dummy-package"),
                affected_version_range=VersionRange.from_string("vers:pypi/>=1.0.0|<=2.0.0"),
            )
        ],
        references=[ReferenceV2(url="https://example.com/with/more/info/CVE-2020-13371337")],
        date_published=timezone.now(),
        url="https://test.com",
    )
]


class DummyImporter(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "dummy_import_runner_v2"
    license_url = "https://example.com/license"
    datasource_id = "dummy_import_runner"
    spdx_license_expression = "CC-BY-4.0"

    def collect_advisories(self):
        return ADVISORY_DATAS

    def advisories_count(self):
        return len(ADVISORY_DATAS)


class EmptyImporter(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "empty_import_runner_v2"
    license_url = "https://example.com/license"
    datasource_id = "empty_import_runner"
    spdx_license_expression = "CC-BY-4.0"

    def collect_advisories(self):
        return []

    def advisories_count(self):
        return 0


@pytest.mark.django_db
def test_import_runner_1():
    status, error = DummyImporter().execute()
    assert status == 0, error
    advisories = models.AdvisoryV2.objects.all()
    assert advisories.count() == 1
    assert advisories.first().advisory_id == "CVE-2020-1337137"


@pytest.mark.django_db
def test_process_advisories_with_no_advisory():
    status, error = EmptyImporter().execute()
    assert status == 0, error
    assert 0 == models.AdvisoryV2.objects.count()


@pytest.mark.django_db
def test_process_advisories_with_advisories():
    status, error = DummyImporter().execute()
    assert status == 0, error
    advisories = models.AdvisoryV2.objects.all()
    assert advisories.count() == 1
    assert advisories.first().summary == "vulnerability description here"
