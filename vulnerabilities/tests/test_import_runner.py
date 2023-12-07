#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest
from django.utils import timezone
from univers.version_range import VersionRange

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.import_runner import process_inferences
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import PackageURL
from vulnerabilities.importer import Reference
from vulnerabilities.improver import Inference
from vulnerabilities.tests.test_improve_runner import (
    get_objects_in_all_tables_used_by_process_inferences,
)

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
        date_published=timezone.now(),
    )
]


class DummyImporter(Importer):
    spdx_license_expression = "dummy license"

    def advisory_data(self):
        return ADVISORY_DATAS


@pytest.mark.django_db(transaction=True)
def test_import_runner(db):
    runner = ImportRunner(DummyImporter)
    runner.run()
    advisories = models.Advisory.objects.all()
    advisory_datas = [x.to_advisory_data() for x in advisories]
    assert advisory_datas == ADVISORY_DATAS


@pytest.mark.django_db(transaction=True)
def test_process_advisories_with_no_advisory(db):
    ImportRunner(DummyImporter).process_advisories([], "")
    assert 0 == models.Advisory.objects.count()


@pytest.mark.django_db(transaction=True)
def test_process_advisories_with_advisories(db):
    ImportRunner(DummyImporter).process_advisories(ADVISORY_DATAS, "test_importer")
    advisories = models.Advisory.objects.all()
    advisory_datas = [x.to_advisory_data() for x in advisories]
    assert advisory_datas == ADVISORY_DATAS


@pytest.mark.django_db(transaction=True)
def test_process_advisories_idempotency(db):
    ImportRunner(DummyImporter).process_advisories(ADVISORY_DATAS, "test_importer")
    ImportRunner(DummyImporter).process_advisories(ADVISORY_DATAS, "test_importer")
    ImportRunner(DummyImporter).process_advisories(ADVISORY_DATAS, "test_importer")
    advisories = models.Advisory.objects.all()
    advisory_datas = [x.to_advisory_data() for x in advisories]
    assert advisory_datas == ADVISORY_DATAS


@pytest.mark.django_db(transaction=True)
def test_process_advisories_idempotency_with_one_new_advisory(db):
    advisory_datas = ADVISORY_DATAS.copy()
    ImportRunner(DummyImporter).process_advisories(advisory_datas, "test_importer")
    advisory_datas.append(
        AdvisoryData(
            aliases=["CVE-2022-1337"],
        )
    )
    ImportRunner(DummyImporter).process_advisories(advisory_datas, "test_importer")
    advisories = models.Advisory.objects.all()
    advisory_datas_in_db = [x.to_advisory_data() for x in advisories]
    assert advisory_datas_in_db == advisory_datas


@pytest.mark.django_db(transaction=True)
def test_process_advisories_idempotency_with_different_importer_names():
    ImportRunner(DummyImporter).process_advisories(ADVISORY_DATAS, "test_importer_one")
    ImportRunner(DummyImporter).process_advisories(ADVISORY_DATAS, "test_importer_two")
    advisories = models.Advisory.objects.all()
    advisory_datas = [x.to_advisory_data() for x in advisories]
    assert advisory_datas == ADVISORY_DATAS


def test_advisory_summary_clean_up():
    adv = AdvisoryData(
        summary="The X509Extension in pyOpenSSL before 0.13.1 does not properly handle a '\x00' character in a domain name in the Subject Alternative Name field of an X.509 certificate, which allows man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority."
    )
    assert "\x00" not in adv.summary


DUMMY_ADVISORY = models.Advisory(summary="dummy", created_by="tests", date_collected=timezone.now())


INFERENCES = [
    Inference(
        aliases=["CVE-1", "CVE-2"],
        summary="One upon a time, in a package far far away",
        affected_purls=[
            PackageURL(type="character", namespace="star-wars", name="anakin", version="1")
        ],
        fixed_purl=PackageURL(
            type="character", namespace="star-wars", name="darth-vader", version="1"
        ),
        references=[Reference(reference_id="imperial-vessel-1", url="https://m47r1x.github.io")],
    )
]


@pytest.mark.django_db
def test_process_inferences_with_no_inference():
    assert not process_inferences(
        inferences=[], advisory=DUMMY_ADVISORY, improver_name="test_improver"
    )


@pytest.mark.django_db
def test_process_inferences_with_unknown_but_specified_vulnerability():
    inference = Inference(vulnerability_id="VCID-Does-Not-Exist-In-DB", aliases=["MATRIX-Neo"])
    assert not process_inferences(
        inferences=[inference], advisory=DUMMY_ADVISORY, improver_name="test_improver"
    )


@pytest.mark.django_db
def test_process_inferences_idempotency():
    process_inferences(INFERENCES, DUMMY_ADVISORY, improver_name="test_improver")
    all_objects = get_objects_in_all_tables_used_by_process_inferences()
    process_inferences(INFERENCES, DUMMY_ADVISORY, improver_name="test_improver")
    process_inferences(INFERENCES, DUMMY_ADVISORY, improver_name="test_improver")
    assert all_objects == get_objects_in_all_tables_used_by_process_inferences()
