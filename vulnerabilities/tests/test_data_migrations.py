# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from django.apps import apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase

from vulnerabilities import severity_systems
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity


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
