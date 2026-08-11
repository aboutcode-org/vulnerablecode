import datetime

from django.test import TestCase
from django.utils import timezone

from insights.charts.data_quality_panel import data_quality_todos_resolutions_queryset
from insights.charts.data_quality_panel import open_issues_to_datasource_queryset
from vulnerabilities.models import AdvisoryToDoV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ToDoRelatedAdvisoryV2


class TestDataQualityPanelQuerysets(TestCase):
    def setUp(self):
        self.adv1 = AdvisoryV2.objects.create(
            avid="github_osv/GHSA-1",
            datasource_id="github_osv",
            unique_content_id="1",
            is_latest=True,
            pipeline_id="github_osv_pipeline",
            advisory_id="GHSA-1",
            url="https://example.com/GHSA-1",
        )
        self.adv2 = AdvisoryV2.objects.create(
            avid="nvd/CVE-2023-1234",
            datasource_id="nvd",
            unique_content_id="2",
            is_latest=True,
            pipeline_id="nvd_pipeline",
            advisory_id="CVE-2023-1234",
            url="https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
        )

        now = timezone.now()

        self.todo1 = AdvisoryToDoV2.objects.create(
            alias="GHSA-1-TODO",
            related_advisories_id="hash1",
            issue_type="MISSING_AFFECTED_PACKAGE",
            is_resolved=False,
            created_at=now - datetime.timedelta(days=60),
        )
        ToDoRelatedAdvisoryV2.objects.create(todo=self.todo1, advisory=self.adv1)

        self.todo2 = AdvisoryToDoV2.objects.create(
            alias="CVE-2023-1234-TODO",
            related_advisories_id="hash2",
            issue_type="CONFLICTING_SEVERITY_SCORES",
            is_resolved=False,
            created_at=now - datetime.timedelta(days=45),
        )
        ToDoRelatedAdvisoryV2.objects.create(todo=self.todo2, advisory=self.adv2)

        self.todo3 = AdvisoryToDoV2.objects.create(
            alias="GHSA-1-TODO-2",
            related_advisories_id="hash3",
            issue_type="CONFLICTING_SEVERITY_SCORES",
            is_resolved=True,
            created_at=now - datetime.timedelta(days=60),
            resolved_at=now - datetime.timedelta(days=15),
        )
        ToDoRelatedAdvisoryV2.objects.create(todo=self.todo3, advisory=self.adv1)

    def test_open_issues_to_datasource_queryset(self):
        """Test open issue query correctly aggregates unresolved to-dos by type and source."""
        qs = list(open_issues_to_datasource_queryset())

        self.assertEqual(len(qs), 2)

        missing_pkg_todo = next(t for t in qs if t["issue_type"] == "MISSING_AFFECTED_PACKAGE")
        self.assertEqual(missing_pkg_todo["advisories__datasource_id"], "github_osv")
        self.assertEqual(missing_pkg_todo["count"], 1)

        conflicting_sev_todo = next(
            t for t in qs if t["issue_type"] == "CONFLICTING_SEVERITY_SCORES"
        )
        self.assertEqual(conflicting_sev_todo["advisories__datasource_id"], "nvd")
        self.assertEqual(conflicting_sev_todo["count"], 1)

    def test_data_quality_todos_resolutions_queryset(self):
        """Test timeline query separately aggregates opened and resolved to-dos by month."""
        open_todos_qs, resolved_todos_qs = data_quality_todos_resolutions_queryset()

        open_todos = list(open_todos_qs)
        resolved_todos = list(resolved_todos_qs)

        self.assertEqual(sum(t["count"] for t in open_todos), 3)
        self.assertEqual(sum(t["count"] for t in resolved_todos), 1)

        resolved = resolved_todos[0]
        self.assertEqual(resolved["advisories__datasource_id"], "github_osv")
        self.assertEqual(resolved["count"], 1)
