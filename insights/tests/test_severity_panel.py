from django.test import TestCase

from insights.charts.severity_panel import iter_severity_insights
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2


class TestSeverityPanelQuerysets(TestCase):
    def test_iter_severity_insights(self):
        advisory1 = AdvisoryV2.objects.create(
            avid="github_osv/GHSA-1",
            datasource_id="github_osv",
            unique_content_id="1",
            is_latest=True,
            pipeline_id="github_osv_pipeline",
            advisory_id="GHSA-1",
            url="https://example.com/GHSA-1",
        )
        severity1 = AdvisorySeverity.objects.create(scoring_system="cvssv3.1", value="9.8")
        advisory1.severities.add(severity1)

        advisory2 = AdvisoryV2.objects.create(
            avid="github_osv/GHSA-2",
            datasource_id="github_osv",
            unique_content_id="2",
            is_latest=True,
            pipeline_id="github_osv_pipeline",
            advisory_id="GHSA-2",
            url="https://example.com/GHSA-2",
        )
        severity2 = AdvisorySeverity.objects.create(scoring_system="cvssv3.1", value="4.5")
        advisory2.severities.add(severity2)

        qs = list(iter_severity_insights())

        self.assertEqual(len(qs), 1)
        insight = qs[0]

        self.assertEqual(insight.buckets[9], 1)
        self.assertEqual(insight.buckets[4], 1)
        self.assertEqual(sum(insight.buckets), 2)
