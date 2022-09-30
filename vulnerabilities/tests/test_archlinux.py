#
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from unittest.mock import patch

from django.test import TestCase

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importers import archlinux

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


class ArchlinuxImportTest(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        fixture_path = os.path.join(TEST_DATA, "archlinux.json")
        with open(fixture_path) as f:
            cls.mock_response = json.load(f)

        cls.importer = models.Importer.objects.create(
            name="archlinux_unittests",
            license="",
            last_run=None,
            data_source="ArchlinuxImporter",
            data_source_cfg={
                "archlinux_tracker_url": "https://security.example.com/json",
            },
        )

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def test_import(self):
        runner = ImportRunner(self.importer, 5)

        with patch(
            "vulnerabilities.importers.ArchlinuxImporter._fetch", return_value=self.mock_response
        ):
            runner.run()
        assert models.Vulnerability.objects.count() == 6
        assert models.VulnerabilityReference.objects.count() == 10
        assert models.PackageRelatedVulnerability.objects.all().count() == 12
        assert (
            models.PackageRelatedVulnerability.objects.filter(patched_package__isnull=False).count()
            == 8
        )
        assert models.Package.objects.count() == 10

        self.assert_for_package(
            "squid",
            "4.10-2",
            cve_ids={"CVE-2020-11945", "CVE-2019-12521", "CVE-2019-12519"},
        )
        self.assert_for_package("openconnect", "1:8.05-1", cve_ids={"CVE-2020-12823"})
        self.assert_for_package(
            "wireshark-common",
            "2.6.0-1",
            cve_ids={"CVE-2018-11362", "CVE-2018-11361"},
        )
        self.assert_for_package(
            "wireshark-gtk",
            "2.6.0-1",
            cve_ids={"CVE-2018-11362", "CVE-2018-11361"},
        )
        self.assert_for_package(
            "wireshark-cli",
            "2.6.0-1",
            cve_ids={"CVE-2018-11362", "CVE-2018-11361"},
        )
        self.assert_for_package(
            "wireshark-qt",
            "2.6.0-1",
            cve_ids={"CVE-2018-11362", "CVE-2018-11361"},
        )
        self.assert_for_package("wireshark-common", "2.6.1-1")
        self.assert_for_package("wireshark-gtk", "2.6.1-1")
        self.assert_for_package("wireshark-cli", "2.6.1-1")
        self.assert_for_package("wireshark-qt", "2.6.1-1")

    def assert_for_package(self, name, version, cve_ids=None):
        qs = models.Package.objects.filter(
            name=name,
            version=version,
            type="pacman",
            namespace="archlinux",
        )
        assert qs

        if cve_ids:
            assert cve_ids == {v.vulnerability_id for v in qs[0].vulnerabilities.all()}


# 9/28/2022 Wednesday 12:45:59 PM.  https://security.archlinux.org/json -- view in Firefox, copy, paste, change null to None
def test_parse_advisory():
    record = {
        "name": "AVG-2781",
        "packages": ["python-pyjwt"],
        "status": "Unknown",
        "severity": "Unknown",
        "type": "unknown",
        "affected": "2.3.0-1",
        "fixed": "2.4.0-1",
        "ticket": None,
        "issues": ["CVE-2022-29217"],
        "advisories": [],
    }

    assert archlinux.ArchlinuxImporter().parse_advisory(record)


# 9/29/2022 Thursday 9:08:38 PM.
def test_parse_advisory_multi():
    # record = {
    #     "name": "AVG-2781",
    #     "packages": ["python-pyjwt"],
    #     "status": "Unknown",
    #     "severity": "Unknown",
    #     "type": "unknown",
    #     "affected": "2.3.0-1",
    #     "fixed": "2.4.0-1",
    #     "ticket": None,
    #     "issues": ["CVE-2022-29217"],
    #     "advisories": [],
    # }

    record_list = [
        {
            "name": "AVG-2781",
            "packages": ["python-pyjwt"],
            "status": "Unknown",
            "severity": "Unknown",
            "type": "unknown",
            "affected": "2.3.0-1",
            "fixed": "2.4.0-1",
            "ticket": None,
            "issues": ["CVE-2022-29217"],
            "advisories": [],
        },
        {
            "name": "AVG-2780",
            "packages": ["wpewebkit"],
            "status": "Unknown",
            "severity": "Unknown",
            "type": "unknown",
            "affected": "2.36.3-1",
            "fixed": "2.36.4-1",
            "ticket": None,
            "issues": ["CVE-2022-26710", "CVE-2022-22677", "CVE-2022-22662"],
            "advisories": [],
        },
        {
            "name": "AVG-4",
            "packages": ["bzip2"],
            "status": "Fixed",
            "severity": "Low",
            "type": "denial of service",
            "affected": "1.0.6-5",
            "fixed": "1.0.6-6",
            "ticket": None,
            "issues": ["CVE-2016-3189"],
            "advisories": ["ASA-201702-19"],
        },
    ]

    assert archlinux.ArchlinuxImporter().parse_advisory(record_list)
