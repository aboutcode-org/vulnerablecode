#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import shutil
import tempfile
import zipfile
from unittest.mock import patch

from django.test import TestCase

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


@patch("vulnerabilities.importers.MozillaImporter._update_from_remote")
class MozillaImportTest(TestCase):

    tempdir = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.tempdir = tempfile.mkdtemp()
        zip_path = os.path.join(TEST_DATA, "mozilla.zip")

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(cls.tempdir)

        cls.importer = models.Importer.objects.create(
            name="mozilla_unittests",
            license="",
            last_run=None,
            data_source="MozillaImporter",
            data_source_cfg={
                "repository_url": "https://example.git",
                "working_directory": os.path.join(cls.tempdir, "mozilla_test"),
                "create_working_directory": False,
                "remove_working_directory": False,
            },
        )

    @classmethod
    def tearDownClass(cls) -> None:
        # Make sure no requests for unexpected package names have been made during the tests.
        shutil.rmtree(cls.tempdir)

    def test_import(self, _):
        runner = ImportRunner(self.importer, 100)

        # Remove if we don't need set_api in MozillaImporter
        # with patch("vulnerabilities.importers.MozillaImporter.versions", new=MOCK_VERSION_API):
        #     with patch("vulnerabilities.importers.MozillaImporter.set_api"):
        #         runner.run()
        runner.run()

        assert models.Vulnerability.objects.count() == 9
        assert models.VulnerabilityReference.objects.count() == 10
        assert models.VulnerabilitySeverity.objects.count() == 9
        assert models.PackageRelatedVulnerability.objects.filter(is_vulnerable=False).count() == 16

        assert models.Package.objects.count() == 12

        self.assert_for_package("Firefox ESR", "mfsa2021-06", "78.7.1")
        self.assert_for_package("Firefox ESR", "mfsa2021-04", "78.7", "CVE-2021-23953")
        self.assert_for_package("Firefox for Android", "mfsa2021-01", "84.1.3", "CVE-2020-16044")
        self.assert_for_package("Thunderbird", "mfsa2014-30", "24.4")
        self.assert_for_package("Thunderbird", "mfsa2014-30", "24.4")
        self.assert_for_package("Mozilla Suite", "mfsa2005-29", "1.7.6")

    def assert_for_package(
        self,
        package_name,
        mfsa_id,
        resolved_version,
        vulnerability_id=None,
        impacted_version=None,
    ):

        pkg = models.Package.objects.get(name=package_name, version=resolved_version)
        vuln = pkg.vulnerabilities.first()

        if vulnerability_id:
            assert vuln.vulnerability_id == vulnerability_id

        ref_url = f"https://www.mozilla.org/en-US/security/advisories/{mfsa_id}"
        assert models.VulnerabilityReference.objects.get(url=ref_url, vulnerability=vuln)

        assert models.PackageRelatedVulnerability.objects.filter(
            package=pkg, vulnerability=vuln, is_vulnerable=False
        )


def test_categorize_versions_ranges():
    # Populate if impacted version is filled
    pass
