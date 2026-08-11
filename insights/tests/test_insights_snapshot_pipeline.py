from django.test import TestCase
from django.utils import timezone

from insights.insights_snapshot_pipeline import InsightsSnapshotPipeline
from insights.models import DailySnapshot
from insights.tests.test_importer_panel import create_adv
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryToDoV2
from vulnerabilities.models import PackageV2
from vulnerabilities.models import ToDoRelatedAdvisoryV2


class TestInsightsSnapshotPipeline(TestCase):
    def test_pipeline_execution_with_data(self):
        """Test pipeline populates insights based on existing data."""

        PackageV2.objects.create(type="pypi", name="django", version="1.0.0")
        PackageV2.objects.create(type="npm", name="lodash", version="1.0.0")

        # Create Advisory for Importer and Severity charts
        advisory_1 = create_adv("GHSA-1234", "1")
        advisory_1.date_published = timezone.now()
        advisory_1.save()
        severity_1 = AdvisorySeverity.objects.create(scoring_system="cvssv3.1", value="9.8")
        advisory_1.severities.add(severity_1)

        todo = AdvisoryToDoV2.objects.create(
            alias="GHSA-1234-TODO",
            related_advisories_id="hash1",
            issue_type="MISSING_AFFECTED_PACKAGE",
            is_resolved=False,
            created_at=timezone.now(),
        )
        ToDoRelatedAdvisoryV2.objects.create(todo=todo, advisory=advisory_1)

        pipeline = InsightsSnapshotPipeline()
        pipeline.execute()

        self.assertEqual(DailySnapshot.objects.count(), 1)
        snapshot = DailySnapshot.objects.first()

        # Verify captured package types (pypi, npm) and 'global'
        self.assertEqual(snapshot.package_insights.count(), 3)

        # Verify ImporterInsight was created for 'github_osv'
        self.assertEqual(snapshot.importer_insights.count(), 1)
        self.assertTrue(snapshot.importer_insights.filter(importer="github_osv").exists())

        # Verify SeverityInsight was generated
        self.assertTrue(hasattr(snapshot, "severity_insight"))
        self.assertEqual(snapshot.severity_insight.buckets[9], 1)

        self.assertTrue(hasattr(snapshot, "overview"))
        self.assertEqual(snapshot.overview.total_advisories, 1)
        self.assertEqual(len(snapshot.overview.last_30days), 31)
        self.assertEqual(snapshot.overview.yearly_insights.count(), 1)

        self.assertEqual(snapshot.data_quality_issue_types.count(), 1)
        self.assertEqual(snapshot.data_quality_issue_types.first().datasource_id, "github_osv")
        self.assertEqual(snapshot.data_quality_todos_resolutions.count(), 1)
