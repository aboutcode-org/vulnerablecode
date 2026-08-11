import datetime

from django.test import TestCase
from django.utils import timezone

from insights.charts.overview_panel import daily_growth_counts
from insights.charts.overview_panel import kpi_card_queryset
from insights.charts.overview_panel import yearly_distribution_queryset
from insights.tests.test_importer_panel import create_adv
from vulnerabilities.models import PackageV2


class TestOverviewPanelQuerysets(TestCase):
    def setUp(self):
        PackageV2.objects.create(type="pypi", name="django", version="1.0.0")
        PackageV2.objects.create(type="npm", name="lodash", version="1.0.0")

        self.now = timezone.now()

        adv1 = create_adv("GHSA-1234", "1")
        adv1.date_published = self.now - datetime.timedelta(days=365 * 2)
        adv1.date_collected = self.now - datetime.timedelta(days=5)
        adv1.datasource_id = "github_osv"
        adv1.save()

        adv2 = create_adv("GHSA-5678", "2")
        adv2.date_published = self.now
        adv2.date_collected = self.now
        adv2.datasource_id = "github_osv"
        adv2.save()

        adv3 = create_adv("CVE-2023-7777", "3")
        adv3.date_published = self.now - datetime.timedelta(days=10)
        adv3.date_collected = self.now
        adv3.datasource_id = "nvd"
        adv3.save()

        adv4 = create_adv("CVE-2024-9999", "4")
        adv4.date_published = self.now
        adv4.date_collected = self.now
        adv4.datasource_id = "nvd"
        adv4.save()

        adv5 = create_adv("CVE-2024-8888", "5")
        adv5.date_published = self.now
        adv5.date_collected = self.now
        adv5.datasource_id = "nvd"
        adv5.save()

    def test_kpi_card_queryset(self):
        """Test KPI queries"""
        stats = kpi_card_queryset()
        self.assertEqual(stats["total_advisories"], 5)
        self.assertEqual(stats["total_packages"], 2)
        self.assertEqual(stats["total_data_sources"], 2)

    def test_yearly_distribution_queryset(self):
        """Test yearly distribution query aggregates advisories by publish year."""
        yearly_records = list(yearly_distribution_queryset())
        self.assertEqual(len(yearly_records), 2)

        this_year = next(y for y in yearly_records if y["year"] == self.now.year)
        two_years_ago = next(y for y in yearly_records if y["year"] == self.now.year - 2)

        self.assertEqual(this_year["count"], 4)
        self.assertEqual(two_years_ago["count"], 1)

    def test_daily_growth_counts(self):
        """Test daily ingestion query"""
        counts = daily_growth_counts(self.now)
        self.assertEqual(sum(counts), 5)
