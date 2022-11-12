#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.apps import apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase

from vulnerabilities import severity_systems


class TestMigrations(TestCase):
    @property
    def app(self):
        return apps.get_containing_app_config(type(self).__module__).name

    migrate_from = None
    migrate_to = None

    def setUp(self):
        assert (
            self.migrate_from and self.migrate_to
        ), "TestCase '{}' must define migrate_from and migrate_to properties".format(
            type(self).__name__
        )
        self.migrate_from = [(self.app, self.migrate_from)]
        self.migrate_to = [(self.app, self.migrate_to)]
        executor = MigrationExecutor(connection)
        old_apps = executor.loader.project_state(self.migrate_from).apps

        # # Reverse to the original migration
        executor.migrate(self.migrate_from)

        self.setUpBeforeMigration(old_apps)

        # Run the migration to test
        executor = MigrationExecutor(connection)
        executor.loader.build_graph()  # reload.
        executor.migrate(self.migrate_to)

        self.apps = executor.loader.project_state(self.migrate_to).apps

    def setUpBeforeMigration(self, apps):
        pass


class DuplicateSeverityTestCase(TestMigrations):
    migrate_from = "0013_auto_20220503_0941"
    migrate_to = "0014_remove_duplicate_severities"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        Severities = apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        Vulnerability = apps.get_model("vulnerabilities", "Vulnerability")

        reference = VulnerabilityReference.objects.create(
            reference_id="CVE-TEST", url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-TEST"
        )
        self.reference = reference
        vulnerability1 = Vulnerability(vulnerability_id=1, summary="test-1")
        vulnerability1.save()
        vulnerability2 = Vulnerability(vulnerability_id=2, summary="test-2")
        vulnerability2.save()
        vulnerability3 = Vulnerability(vulnerability_id=3, summary="test-3")
        vulnerability3.save()
        Severities.objects.update_or_create(
            vulnerability=vulnerability1,
            scoring_system=severity_systems.REDHAT_AGGREGATE.identifier,
            reference=reference,
            defaults={"value": str("TEST")},
        )
        Severities.objects.update_or_create(
            vulnerability=vulnerability2,
            scoring_system=severity_systems.REDHAT_AGGREGATE.identifier,
            reference=reference,
            defaults={"value": str("TEST")},
        )
        Severities.objects.update_or_create(
            vulnerability=vulnerability3,
            scoring_system=severity_systems.REDHAT_AGGREGATE.identifier,
            reference=reference,
            defaults={"value": str("TEST")},
        )

    def test_remove_duplicate_rows(self):
        VulnerabilitySeverity = self.apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        assert len(VulnerabilitySeverity.objects.filter(reference=self.reference.id)) == 1


class DropVulnerabilityFromSeverityTestCase(TestMigrations):
    migrate_from = "0014_remove_duplicate_severities"
    migrate_to = "0015_alter_vulnerabilityseverity_unique_together_and_more"

    def test_dropping_vulnerability_from_severity(self):
        # using get_model to avoid circular import
        VulnerabilityReference = self.apps.get_model("vulnerabilities", "VulnerabilityReference")
        VulnerabilitySeverity = self.apps.get_model("vulnerabilities", "VulnerabilitySeverity")

        reference = VulnerabilityReference.objects.create(
            reference_id="CVE-TEST", url="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-TEST"
        )
        VulnerabilitySeverity.objects.update_or_create(
            scoring_system=severity_systems.REDHAT_AGGREGATE.identifier,
            reference=reference,
            defaults={"value": str("TEST")},
        )


class UpdateCPEURL(TestMigrations):
    migrate_from = "0015_alter_vulnerabilityseverity_unique_together_and_more"
    migrate_to = "0016_update_cpe_url"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")

        reference = VulnerabilityReference.objects.create(
            reference_id="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", url=""
        )
        reference.save()
        self.reference = reference

    def test_cpe_url_update(self):
        # using get_model to avoid circular import
        VulnerabilityReference = self.apps.get_model("vulnerabilities", "VulnerabilityReference")
        ref = VulnerabilityReference.objects.get(reference_id=self.reference.reference_id)
        assert (
            ref.url
            == "https://nvd.nist.gov/vuln/search/results?adv_search=true&isCpeNameSearch=true&query=cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        )


class TestScoringElement(TestMigrations):
    migrate_from = "0031_vulnerabilityseverity_scoring_elements"
    migrate_to = "0032_vulnerabilityseverity_compute_score"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilitySeverity = apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        reference = VulnerabilityReference.objects.create(
            id=1, reference_id="fake-reference_id", url="fake-url"
        )
        reference.save()
        self.reference = reference
        self.severity_list = [
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2_VECTOR.identifier,
                value="AV:N/AC:L/Au:N/C:P/I:P/A:P",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV3_VECTOR.identifier,
                value="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV31_VECTOR.identifier,
                value="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2_VECTOR.identifier,
                value="",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="generic_textual",
                value="Low",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="rhbs",
                value="medium",
                reference_id=1,
            ),
        ]
        for severity in self.severity_list:
            severity.save()

    def test_cvss_calculations(self):
        # using get_model to avoid circular import
        VulnerabilitySeverity = self.apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        severity = VulnerabilitySeverity.objects.filter(reference_id=1).order_by("-scoring_system")
        self.assertEqual(
            [severity[i].scoring_elements for i in range(0, 6)],
            [None, None, "7.5", "9.8", "7.5", None],
        )


class TestRemoveExtraRows(TestMigrations):
    migrate_from = "0032_vulnerabilityseverity_compute_score"
    migrate_to = "0033_vulnerabilityseverity_rm_extra_records_swap"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilitySeverity = apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        self.reference_list = [
            VulnerabilityReference.objects.create(
                id=1,
                reference_id="fake-reference_id1",
                url="fake-url1",
            ),
            VulnerabilityReference.objects.create(
                id=2,
                reference_id="fake-reference_id2",
                url="fake-url2",
            ),
            VulnerabilityReference.objects.create(
                id=3,
                reference_id="fake-reference_id3",
                url="fake-url3",
            ),
            VulnerabilityReference.objects.create(
                id=4,
                reference_id="fake-reference_id4",
                url="fake-url4",
            ),
        ]

        for reference in self.reference_list:
            reference.save()

        self.severity_list = [
            # test severity_cvss2
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2.identifier,
                value="7.5",
                reference_id=1,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2_VECTOR.identifier,
                value="AV:N/AC:L/Au:N/C:P/I:P/A:P",
                scoring_elements="7.5",
                reference_id=1,
            ),
            # test severity_cvss3
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV3.identifier,
                value="7.5",
                reference_id=2,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV3_VECTOR.identifier,
                value="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                scoring_elements="7.5",
                reference_id=2,
            ),
            # test severity_cvss3_1
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV31.identifier,
                value="9.8",
                reference_id=3,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV31_VECTOR.identifier,
                value="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                scoring_elements="9.8",
                reference_id=3,
            ),
            # test all type of severities for the same reference_id 4
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2.identifier,
                value="7.5",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV2_VECTOR.identifier,
                value="AV:N/AC:L/Au:N/C:P/I:P/A:P",
                scoring_elements="7.5",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV3.identifier,
                value="7.5",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV3_VECTOR.identifier,
                value="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                scoring_elements="7.5",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV31.identifier,
                value="9.8",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system=severity_systems.CVSSV3_VECTOR.identifier,
                value="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                scoring_elements="9.8",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="generic_textual",
                value="Low",
                reference_id=4,
            ),
            VulnerabilitySeverity.objects.create(
                scoring_system="rhbs",
                value="medium",
                reference_id=4,
            ),
        ]

        for severity in self.severity_list:
            severity.save()

    def test_rm_extra_records_and_swap(self):
        # using get_model to avoid circular import
        VulnerabilitySeverity = self.apps.get_model("vulnerabilities", "VulnerabilitySeverity")

        severity_cvss2 = VulnerabilitySeverity.objects.values("scoring_elements", "value").get(
            reference_id=1
        )
        expected = {"scoring_elements": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "value": "7.5"}
        assert severity_cvss2 == expected

        severity_cvss3 = VulnerabilitySeverity.objects.values("scoring_elements", "value").get(
            reference_id=2
        )

        expected = {
            "scoring_elements": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "value": "7.5",
        }
        assert severity_cvss3 == expected

        severity_cvss3_1 = VulnerabilitySeverity.objects.values("scoring_elements", "value").get(
            reference_id=3
        )

        expected = {
            "scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "value": "9.8",
        }
        assert severity_cvss3_1 == expected

        severities = list(
            VulnerabilitySeverity.objects.filter(reference_id=4).values("scoring_elements", "value")
        )

        expected = [
            {"scoring_elements": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "value": "7.5"},
            {"scoring_elements": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "value": "7.5"},
            {"scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "value": "9.8"},
            {"scoring_elements": None, "value": "Low"},
            {"scoring_elements": None, "value": "medium"},
        ]
        assert severities == expected
