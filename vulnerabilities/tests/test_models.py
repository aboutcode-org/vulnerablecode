#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest import TestCase
from unittest.mock import patch

import pytest
from django.db.utils import IntegrityError
from django.test import TestCase as DjangoTestCase
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities import models
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import PatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import PackageV2
from vulnerabilities.models import Patch
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import CVSSV4
from vulnerabilities.tests.pipelines import TestLogger


class TestPipelineRunModel(DjangoTestCase):
    def setUp(self):
        self.schedule1 = models.PipelineSchedule.objects.create(pipeline_id="test_pipeline")
        self.run1 = models.PipelineRun.objects.create(pipeline=self.schedule1)

    def test_pipelinerun_set_run_failed(self):
        self.run1.set_run_ended(exitcode=1, output="some failure")
        self.assertTrue(self.run1.run_failed)

    def test_pipelinerun_set_run_queued(self):
        self.assertEqual(self.run1.status, self.run1.Status.QUEUED)

    def test_pipelinerun_set_running(self):
        self.run1.set_run_started()
        self.assertEqual(self.run1.status, self.run1.Status.RUNNING)

    @patch("vulnerabilities.tasks.dequeue_job", return_value="")
    def test_pipelinerun_stopped(self, mock_dequeue):
        self.run1.stop_run()
        self.assertEqual(self.run1.status, self.run1.Status.STOPPED)

    def test_pipelinerun_success(self):
        self.run1.set_run_ended(exitcode=0)
        self.assertEqual(self.run1.status, self.run1.Status.SUCCESS)

    def test_pipelinerun_schedules_mark_stale_runs_unfinished_job(self):
        from vulnerabilities.schedules import mark_stale_runs

        self.run1.set_run_started()
        self.assertEqual(self.run1.run_exitcode, None)
        mark_stale_runs()
        self.run1.refresh_from_db()
        self.assertEqual(self.run1.run_exitcode, 88)

    def test_pipelinerun_schedules_mark_stale_runs_job_not_yet_started(self):
        from vulnerabilities.schedules import mark_stale_runs

        self.assertEqual(self.run1.run_exitcode, None)
        mark_stale_runs()
        self.run1.refresh_from_db()
        self.assertEqual(self.run1.run_exitcode, None)


class TestPipelineScheduleModel(DjangoTestCase):
    def setUp(self):
        self.schedule1 = models.PipelineSchedule.objects.create(pipeline_id="test_pipeline")
        self.run1 = models.PipelineRun.objects.create(pipeline=self.schedule1)
        self.run1.set_run_started()
        self.run1.set_run_ended(exitcode=0)
        self.run2 = models.PipelineRun.objects.create(pipeline=self.schedule1)
        self.run2.set_run_started()

    def test_pipelineschedule_status(self):
        self.assertEqual(self.schedule1.status, "running")

    def test_pipelineschedule_latest_run_date(self):
        self.run2.set_run_started()
        self.assertEqual(self.schedule1.latest_run_date, self.run2.run_start_date)

    def test_pipelineschedule_all_runs(self):
        self.assertEqual(self.schedule1.all_runs.count(), 2)


class PatchConstraintTests(TestCase):
    @pytest.mark.django_db
    def test_constraint_none(self):
        with self.assertRaises(IntegrityError) as raised:
            Patch.objects.create(patch_url=None, patch_text=None)
        self.assertIn("patch_url_or_patch_text", str(raised.exception))

    @pytest.mark.django_db
    def test_constraint_empty(self):
        with self.assertRaises(IntegrityError) as raised:
            Patch.objects.create(patch_url="", patch_text="")
        self.assertIn("patch_url_or_patch_text", str(raised.exception))

    @pytest.mark.django_db
    def test_constraint_empty_none(self):
        with self.assertRaises(IntegrityError) as raised:
            Patch.objects.create(patch_url="", patch_text=None)
        self.assertIn("patch_url_or_patch_text", str(raised.exception))

    @pytest.mark.django_db
    def test_constraint_none_empty(self):
        with self.assertRaises(IntegrityError) as raised:
            Patch.objects.create(patch_url=None, patch_text="")
        self.assertIn("patch_url_or_patch_text", str(raised.exception))


class TestStoreLongCVSSV4(TestCase):
    @pytest.mark.django_db
    def test_constraint_none(self):
        AdvisorySeverity.objects.create(
            scoring_system=CVSSV4,
            scoring_elements="CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
        )
        AdvisorySeverity.objects.create(
            scoring_system=CVSSV4,
            scoring_elements="CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:H/SC:H/SI:L/SA:L/E:A/CR:M/IR:M/AR:M/MAV:A/MAC:L/MAT:P/MPR:L/MVC:L/MVI:L/MVA:L/MSC:H/MSI:H/MSA:H/S:P/AU:Y/R:U/V:C/RE:M/U:Amber",
        )


class TestAdvisoryV2Model(DjangoTestCase):
    def setUp(self):
        self.logger = TestLogger()
        self.advisoryv2_data1 = AdvisoryDataV2(
            advisory_id="test_adv",
            aliases=[],
            summary="vulnerability description here",
            affected_packages=[
                AffectedPackageV2(
                    package=PackageURL(type="pypi", name="dummy"),
                    affected_version_range=VersionRange.from_string("vers:pypi/>=1.0.0|<=2.0.0"),
                    introduced_by_commit_patches=[
                        PackageCommitPatchData(
                            vcs_url="http://foo.bar/", commit_hash="c4eab154606e801"
                        )
                    ],
                )
            ],
            references=[ReferenceV2(url="https://example.com/with/more/info/CVE-2020-13371337")],
            patches=[PatchData(patch_url="https://foo.bar/", patch_text="test patch")],
            url="https://test.com",
        )

    def test_advisoryv2_to_advisory_data_patch_seralization(self):
        from vulnerabilities.pipes.advisory import insert_advisory_v2

        insert_advisory_v2(
            advisory=self.advisoryv2_data1,
            pipeline_id="test_pipeline",
            logger=self.logger.write,
            datasource_id="test",
        )
        result = models.AdvisoryV2.objects.first().to_advisory_data()

        self.assertEqual(result, self.advisoryv2_data1)


class TestAdvisoryV2ModelDuplication(DjangoTestCase):
    def setUp(self):
        self.logger = TestLogger()
        self.advisoryv2_data1 = AdvisoryDataV2(
            advisory_id="CVE-2023-0401",
            aliases=[],
            summary="CVE-2023-0401 advisory",
            affected_packages=[],
            severities=[
                VulnerabilitySeverity(
                    system=CVSSV3,
                    value="7.5",
                    scoring_elements="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                )
            ],
            patches=[],
            url="https://test.com",
        )

        self.advisoryv2_data2 = AdvisoryDataV2(
            advisory_id="CVE-2023-0662",
            aliases=[],
            summary="CVE-2023-0662 advisory",
            affected_packages=[],
            severities=[
                VulnerabilitySeverity(
                    system=CVSSV3,
                    value="7.5",
                    scoring_elements="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                )
            ],
            patches=[],
            url="https://test.com",
        )

    def test_advisoryv2_duplication_data(self):
        from vulnerabilities.pipes.advisory import insert_advisory_v2

        insert_advisory_v2(
            advisory=self.advisoryv2_data1,
            pipeline_id="test_pipeline",
            logger=self.logger.write,
            datasource_id="test",
        )
        insert_advisory_v2(
            advisory=self.advisoryv2_data2,
            pipeline_id="test_pipeline",
            logger=self.logger.write,
            datasource_id="test",
        )
        result = models.AdvisoryV2.objects.count()

        self.assertEqual(result, 2)


class TestPackageV2BulkCreate(DjangoTestCase):
    def setUp(self):
        PackageV2.objects.get_or_create_from_purl(
            "pkg:deb/ubuntu/linux@6.17.0-19.19?arch=source&distro=questing"
        )
        PackageV2.objects.get_or_create_from_purl("pkg:pypi/foo@1.2.3")
        PackageV2.objects.get_or_create_from_purl("pkg:npm/foobar@3.2.3")
        PackageV2.objects.get_or_create_from_purl("pkg:maven/foo@1.2.3")
        PackageV2.objects.get_or_create_from_purl(
            "pkg:deb/ubuntu/linux@6.17.0-4.4?arch=source&distro=questing"
        )

    def test_package_bulk_get_or_create_from_purls(self):
        purls = [
            "pkg:npm/foo@1.2.3",
            "pkg:pypi/foo@1.2.3",
            "pkg:npm/foobar@3.2.3",
            "pkg:maven/foo@1.2.3",
            "pkg:nuget/foo@1.2.3",
            "pkg:deb/ubuntu/linux@6.17.0-22.22?arch=source&distro=questing",
            "pkg:deb/ubuntu/linux@6.17.0-20.20?arch=source&distro=questing",
            "pkg:deb/ubuntu/linux@6.17.0-14.14?arch=source&distro=questing",
            "pkg:deb/ubuntu/linux@6.17.0-12.12?arch=source&distro=questing",
            "pkg:deb/ubuntu/linux@6.17.0-8.8?arch=source&distro=questing",
            "pkg:deb/ubuntu/linux@6.17.0-7.7?arch=source&distro=questing",
            "pkg:deb/ubuntu/linux@6.17.0-6.6?arch=source&distro=questing",
            "pkg:deb/ubuntu/linux@6.17.0-5.5?arch=source&distro=questing",
            "pkg:deb/ubuntu/linux@6.17.0-4.4?arch=source&distro=questing",
        ]
        result_qs = PackageV2.objects.bulk_get_or_create_from_purls(purls)
        result = [p.package_url for p in result_qs]

        self.assertCountEqual(result, purls)
