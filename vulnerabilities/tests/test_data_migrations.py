#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.apps import apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.db.models import Count
from django.test import TestCase

from vulnerabilities import severity_systems


class TestMigrations(TestCase):
    @property
    def app(self):
        return apps.get_containing_app_config(self.app_name).name

    app_name = None
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


# TestCodeCommitMigration removed: CodeCommit was deleted in 0105, and migration
# 0145 irreversibly drops V1 tables so reversing to 0102/0103 is no longer possible.


class TestLatestAdvisoryV2Migration(TestMigrations):
    """Tests is_latest field population on existing v2 advisory."""

    app_name = "vulnerabilities"
    migrate_from = "0120_impactedpackage_last_range_unfurl_at_and_more"
    migrate_to = "0121_advisoryv2_is_latest_alter_advisoryv2_advisory_id_and_more"

    def setUpBeforeMigration(self, apps):
        AdvisoryV2 = apps.get_model("vulnerabilities", "AdvisoryV2")

        AdvisoryV2.objects.create(
            unique_content_id="content_id_old",
            url="https://old.example.com",
            summary="Old advisory",
            advisory_id="test_adv",
            avid="test_pipeline/test_adv",
            datasource_id="test_pipeline",
            # pipeline_id="test_pipeline_v2",
        )

        AdvisoryV2.objects.create(
            unique_content_id="content_id_old2",
            url="https://old.example.com",
            summary="Old 2 advisory",
            advisory_id="test_adv",
            avid="test_pipeline/test_adv",
            datasource_id="test_pipeline",
            # pipeline_id="test_pipeline_v2",
        )

        AdvisoryV2.objects.create(
            unique_content_id="content_id_new",
            url="https://old.example.com",
            summary="New advisory",
            advisory_id="test_adv",
            avid="test_pipeline/test_adv",
            datasource_id="test_pipeline",
            # pipeline_id="test_pipeline_v2",
        )

    def test_no_duplicate_is_latest_for_avid(self):
        AdvisoryV2 = self.apps.get_model("vulnerabilities", "AdvisoryV2")

        duplicate = (
            AdvisoryV2.objects.filter(is_latest=True)
            .values("avid")
            .annotate(cnt=Count("id"))
            .filter(cnt__gt=1)
        )

        self.assertFalse(duplicate.exists())

    def test_latest_is_actually_recent(self):
        AdvisoryV2 = self.apps.get_model("vulnerabilities", "AdvisoryV2")

        latest = AdvisoryV2.objects.get(avid="test_pipeline/test_adv", is_latest=True)
        self.assertEqual("New advisory", latest.summary)


class TestMalformedAliasesAVIDMigration(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0123_alter_packagev2_options_alter_packagev2_package_url_and_more"
    migrate_to = "0124_advisoryv2_remove_malformed_aliases_and_dvisory_id"
    raw_alias_inputs = [
        ("CVE-2023-1111", True),
        ("GHSA-abcd-1234", True),
        ("", False),
        ("(not", False),
        ("applicable)", False),
        ("(BABEL)", False),
        ("(was", False),
        ("--with-systemd)", False),
        ("fixed", False),
        ("printing", False),
        ("(AFS/RX)", False),
        ("unreliably", False),
        ("(ICMP)", False),
        ("CVE", False),
        ("(Not", False),
        ("(RSVP)", False),
        ("libpcap)", False),
        ("(SMB", False),
        ("fix)", False),
        ("(DCCP)", False),
        ("(HNCP)", False),
        ("(+", False),
        ("(IKEv1)", False),
        ("(FrameRelay)", False),
        ("XPTI", False),
        ("CVE_2019-2426", False),
        ("(BGP)", False),
        ("disabled)", False),
        ("(RPL)", False),
        ("regression", False),
        ("actually", False),
        ("(VRRP)", False),
        ("-V)", False),
        ("2025-48379", False),
        ("fixed,", False),
        ("(802.11)", False),
        ("affected,", False),
        ("SMB", False),
        ("(OSPF6)", False),
        ("too", False),
        ("partially", False),
        ("in", False),
        ("(SMB)", False),
        ("but", False),
        ("-", False),
        ("(LDP)", False),
        ("reproduced,", False),
        ("N/A", False),
        ("(tcpdump", False),
        ("requires", False),
        ("(AoE)", False),
        ("(LMP)", False),
        (" CVE-2025-55070", False),
        ("n/a", False),
        ("No CVE assigned", False),
        ("- CVE-2026-26365", False),
    ]

    def setUpBeforeMigration(self, apps):
        AdvisoryV2 = apps.get_model("vulnerabilities", "AdvisoryV2")
        AdvisoryAlias = apps.get_model("vulnerabilities", "AdvisoryAlias")

        for i, (raw_input, _) in enumerate(self.raw_alias_inputs):
            adv = AdvisoryV2.objects.create(
                unique_content_id=f"content_{i}",
                url="https://example.com",
                summary=f"Advisory for {raw_input}",
                advisory_id=raw_input,
                avid=f"alpine_linux_importer_v2/{raw_input}",
                datasource_id="alpine_linux_importer_v2",
                # pipeline_id="test_pipeline_v2",
            )
            alias = AdvisoryAlias.objects.create(alias=raw_input)
            adv.aliases.add(alias)

    def test_migration_processes_malformed_aliases(self):
        AdvisoryV2 = self.apps.get_model("vulnerabilities", "AdvisoryV2")
        AdvisoryAlias = self.apps.get_model("vulnerabilities", "AdvisoryAlias")

        for i, (raw_input, expected_to_survive) in enumerate(self.raw_alias_inputs):
            adv_exists = AdvisoryV2.objects.filter(unique_content_id=f"content_{i}").exists()
            alias_exists = AdvisoryAlias.objects.filter(alias=raw_input).exists()

            if expected_to_survive:
                assert adv_exists == True
                assert alias_exists == True
            else:
                assert adv_exists == False
                assert alias_exists == False


class TestCleanVersRangeMigration(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0124_advisoryv2_remove_malformed_aliases_and_dvisory_id"
    migrate_to = "0125_clean_vers_range_without_constraints"

    def setUpBeforeMigration(self, apps):
        AdvisoryV2 = apps.get_model("vulnerabilities", "AdvisoryV2")
        ImpactedPackage = apps.get_model("vulnerabilities", "ImpactedPackage")
        PackageCommitPatch = apps.get_model("vulnerabilities", "PackageCommitPatch")

        self.advisory1 = AdvisoryV2.objects.create(
            unique_content_id="content_id_old",
            url="https://old.example.com",
            summary="Old advisory",
            advisory_id="test_adv1",
            avid="test_pipeline/test_adv",
            datasource_id="test_pipeline",
            # pipeline_id="test_pipeline_v2",
        )

        self.advisory2 = AdvisoryV2.objects.create(
            unique_content_id="content_id_old2",
            url="https://old.example.com",
            summary="Old 2 advisory",
            advisory_id="test_adv2",
            avid="test_pipeline/test_adv",
            datasource_id="test_pipeline",
            # pipeline_id="test_pipeline_v2",
        )

        ImpactedPackage.objects.create(
            advisory=self.advisory1,
            base_purl="pkg:npm/foobar0",
            affecting_vers="vers:npm/",
            fixed_vers="vers:npm/",
        )

        self.impact1 = ImpactedPackage.objects.create(
            advisory=self.advisory1,
            base_purl="pkg:npm/foobar1",
            affecting_vers="vers:npm/>=5.3.1|<6.0.0",
            fixed_vers="vers:npm/",
        )

        self.impact2 = ImpactedPackage.objects.create(
            advisory=self.advisory1,
            base_purl="pkg:npm/foobar2",
            affecting_vers="vers:npm/",
            fixed_vers="vers:npm/",
        )

        self.pkg_commit_patch1 = PackageCommitPatch.objects.create(
            commit_hash="8c001a11dbcb3eb6d851e18f4cefa080af5fb398",
            vcs_url="https://github.com/aboutcode-org/test1/",
            patch_text="test1",
        )

        self.impact3 = ImpactedPackage.objects.create(
            advisory=self.advisory2,
            base_purl="pkg:npm/foobar3",
            affecting_vers="vers:npm/>5.6.7",
            fixed_vers="vers:npm/5.6.8",
        )

        self.impact2.fixed_by_package_commit_patches.add(self.pkg_commit_patch1)

        self.assertEqual(ImpactedPackage.objects.count(), 4)

    def test_empty_impactepackages_removed(self):
        ImpactedPackage = apps.get_model("vulnerabilities", "ImpactedPackage")

        self.assertEqual(ImpactedPackage.objects.count(), 3)

    def test_empty_fixed_vers_cleaned(self):
        self.impact1.refresh_from_db()
        self.assertEqual(self.impact1.fixed_vers, None)

    def test_empty_affecting_vers_cleaned(self):
        self.impact2.refresh_from_db()
        self.assertEqual(self.impact2.affecting_vers, None)
        self.assertEqual(self.impact2.fixed_vers, None)

    def test_no_change_to_valid_vers(self):
        self.impact3.refresh_from_db()
        self.assertEqual(self.impact3.affecting_vers, "vers:npm/>5.6.7")
        self.assertEqual(self.impact3.fixed_vers, "vers:npm/5.6.8")
        self.assertEqual(self.impact3.advisory.advisory_id, "test_adv2")


class TestAlpineVersSchemeMigration(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0125_clean_vers_range_without_constraints"
    migrate_to = "0126_use_apk_scheme_for_alpine_vers"

    def setUpBeforeMigration(self, apps):
        ImpactedPackage = apps.get_model("vulnerabilities", "ImpactedPackage")
        AdvisoryV2 = apps.get_model("vulnerabilities", "AdvisoryV2")

        self.advisory1 = AdvisoryV2.objects.create(
            unique_content_id="content_id_old",
            url="https://old.example.com",
            summary="Old advisory",
            advisory_id="test_adv1",
            avid="test_pipeline/test_adv",
            datasource_id="test_pipeline",
        )

        self.impact0 = ImpactedPackage.objects.create(
            advisory=self.advisory1,
            base_purl="pkg:apk/foobar0",
            affecting_vers="vers:alpine/<2.3.4-0r",
            fixed_vers="vers:alpine/2.3.4-0",
        )

        self.impact1 = ImpactedPackage.objects.create(
            advisory=self.advisory1,
            base_purl="pkg:apk/foobar1",
            affecting_vers=None,
            fixed_vers="vers:alpine/2.3.4",
        )

        self.impact2 = ImpactedPackage.objects.create(
            advisory=self.advisory1,
            base_purl="pkg:apk/foobar2",
            affecting_vers="vers:alpine/3.4.5",
            fixed_vers=None,
        )

        self.impact3 = ImpactedPackage.objects.create(
            advisory=self.advisory1,
            base_purl="pkg:alpm/foobar2",
            affecting_vers="vers:alpm/0.2.1",
            fixed_vers=None,
        )

        alpine_affecting = ImpactedPackage.objects.filter(
            affecting_vers__startswith="vers:alpine/"
        ).count()
        alpine_fixing = ImpactedPackage.objects.filter(
            affecting_vers__startswith="vers:alpine/"
        ).count()

        self.assertEqual(alpine_affecting, 2)
        self.assertEqual(alpine_fixing, 2)

    def test_empty_fixed_vers_cleaned(self):
        ImpactedPackage = apps.get_model("vulnerabilities", "ImpactedPackage")

        result_apk_affecting = ImpactedPackage.objects.filter(
            affecting_vers__startswith="vers:apk/"
        ).count()
        result_apk_fixing = ImpactedPackage.objects.filter(
            affecting_vers__startswith="vers:apk/"
        ).count()

        result_alpine_affecting = ImpactedPackage.objects.filter(
            affecting_vers__startswith="vers:alpine/"
        ).count()
        result_alpine_fixing = ImpactedPackage.objects.filter(
            affecting_vers__startswith="vers:alpine/"
        ).count()

        self.assertEqual(result_apk_affecting, 2)
        self.assertEqual(result_apk_fixing, 2)

        self.assertEqual(result_alpine_affecting, 0)
        self.assertEqual(result_alpine_fixing, 0)

    def test_no_change_to_non_alpine_vers(self):
        self.impact3.refresh_from_db()

        self.assertEqual(self.impact3.affecting_vers, "vers:alpm/0.2.1")
        self.assertEqual(self.impact3.fixed_vers, None)

    def test_scheme_migration_correctness(self):
        self.impact0.refresh_from_db()
        self.impact1.refresh_from_db()
        self.impact2.refresh_from_db()

        self.assertEqual(self.impact0.affecting_vers, "vers:apk/<2.3.4-0r")
        self.assertEqual(self.impact0.fixed_vers, "vers:apk/2.3.4-0")

        self.assertEqual(self.impact1.affecting_vers, None)
        self.assertEqual(self.impact1.fixed_vers, "vers:apk/2.3.4")

        self.assertEqual(self.impact2.affecting_vers, "vers:apk/3.4.5")
        self.assertEqual(self.impact2.fixed_vers, None)


class TestCleanAdvisorySeverityMigration(TestMigrations):
    app_name = "vulnerabilities"
    migrate_from = "0138_fix_malformed_cvss_vector"
    migrate_to = "0139_cleanup_none_string_in_severity"

    def setUpBeforeMigration(self, apps):
        AdvisoryV2 = apps.get_model("vulnerabilities", "AdvisoryV2")
        ImpactedPackage = apps.get_model("vulnerabilities", "ImpactedPackage")
        AdvisorySeverity = apps.get_model("vulnerabilities", "AdvisorySeverity")

        self.advisory1 = AdvisoryV2.objects.create(
            unique_content_id="b001d1a8952bc056d0161f1dd45dd8f90b25f62c56a887ea21d09fafd78a0f61",
            url="https://old.example.com",
            summary="Old advisory",
            advisory_id="test_adv1",
            avid="test_pipeline/test_adv",
            datasource_id="test_pipeline",
            pipeline_id="test_pipeline_v2",
        )

        ImpactedPackage.objects.create(
            advisory=self.advisory1,
            base_purl="pkg:npm/foobar0",
            affecting_vers="vers:npm/4.3.2",
            fixed_vers="vers:npm/5.0.0",
        )

        self.severity = AdvisorySeverity.objects.create(
            scoring_system=severity_systems.CVSSV4,
            scoring_elements="CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:N/VI:N/VA:N",
            value="None",
        )

        self.advisory1.severities.add(self.severity)

    def test_severity_value_cleaned(self):
        self.severity.refresh_from_db()
        self.assertEqual(self.severity.value, "")

    def test_advisory_content_id_recomputed(self):
        self.advisory1.refresh_from_db()
        # Hash excludes url/advisory_id (compute_content_id_v2); severity value cleaned to "".
        self.assertEqual(
            self.advisory1.unique_content_id,
            "885d5cc15389a644089516b7047dff3716f666a0219befe32938777ae5e686fb",
        )
