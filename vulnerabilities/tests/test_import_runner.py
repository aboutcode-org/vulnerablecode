#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from datetime import timezone

from univers.version_range import VersionRange

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.import_runner import process_advisories
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import PackageURL
from vulnerabilities.importer import Reference

ADVISORY_DATAS = [
    AdvisoryData(
        aliases=["CVE-2020-13371337"],
        summary="vulnerability description here",
        affected_packages=[
            AffectedPackage(
                package=PackageURL(type="pypi", name="dummy package"),
                affected_version_range=VersionRange.from_string("vers:pypi/>=1.0.0|<=2.0.0"),
            )
        ],
        references=[Reference(url="https://example.com/with/more/info/CVE-2020-13371337")],
        date_published=datetime.now(timezone.utc),
    )
]


class DummyImporter(Importer):
    spdx_license_expression = "dummy license"

    def advisory_data(self):
        return ADVISORY_DATAS


def test_import_runner(db):
    runner = ImportRunner(DummyImporter)
    runner.run()
    advisories = models.Advisory.objects.all()
    advisory_datas = [x.to_advisory_data() for x in advisories]
    assert advisory_datas == ADVISORY_DATAS


def test_process_advisories_with_no_advisory(db):
    process_advisories([], "")
    assert 0 == models.Advisory.objects.count()


def test_process_advisories_with_advisories(db):
    process_advisories(ADVISORY_DATAS, "test_importer")
    advisories = models.Advisory.objects.all()
    advisory_datas = [x.to_advisory_data() for x in advisories]
    assert advisory_datas == ADVISORY_DATAS


def test_process_advisories_idempotency(db):
    process_advisories(ADVISORY_DATAS, "test_importer")
    process_advisories(ADVISORY_DATAS, "test_importer")
    process_advisories(ADVISORY_DATAS, "test_importer")
    advisories = models.Advisory.objects.all()
    advisory_datas = [x.to_advisory_data() for x in advisories]
    assert advisory_datas == ADVISORY_DATAS


def test_process_advisories_idempotency_with_one_new_advisory(db):
    advisory_datas = ADVISORY_DATAS.copy()
    process_advisories(advisory_datas, "test_importer")
    advisory_datas.append(
        AdvisoryData(
            aliases=["CVE-2022-1337"],
        )
    )
    process_advisories(advisory_datas, "test_importer")
    advisories = models.Advisory.objects.all()
    advisory_datas_in_db = [x.to_advisory_data() for x in advisories]
    assert advisory_datas_in_db == advisory_datas


def test_process_advisories_idempotency_with_different_importer_names(db):
    process_advisories(ADVISORY_DATAS, "test_importer_one")
    process_advisories(ADVISORY_DATAS, "test_importer_two")
    advisories = models.Advisory.objects.all()
    advisory_datas = [x.to_advisory_data() for x in advisories]
    assert advisory_datas == ADVISORY_DATAS
