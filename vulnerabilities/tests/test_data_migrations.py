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
    migrate_to = "0016_update_cpe_url_and_remove_duplicate_ref_ids"

    def setUpBeforeMigration(self, apps):
        # using get_model to avoid circular import
        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")

        reference = VulnerabilityReference.objects.create(
            reference_id="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", url=""
        )
        reference.save()
        reference1 = VulnerabilityReference.objects.create(
            reference_id="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", url="https://nvd.nist.gov/vuln/search/results?adv_search=true&isCpeNameSearch=true&query=cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        )
        reference1.save()
        self.reference = reference

    def test_cpe_url_updation(self):
        # using get_model to avoid circular import
        VulnerabilityReference = self.apps.get_model("vulnerabilities", "VulnerabilityReference")
        refs = VulnerabilityReference.objects.filter(reference_id = self.reference.reference_id)
        assert refs.count() == 1
        assert refs[0].url == "https://nvd.nist.gov/vuln/search/results?adv_search=true&isCpeNameSearch=true&query=cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
        assert refs[0].reference_id == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
