from django.test import TestCase
from django.urls import reverse

from insights.models import DailySnapshot
from vulnerabilities.models import PackageV2


class TestInsightsViews(TestCase):
    def test_dashboard_redirects_to_default_panel(self):
        """Root insights URL should redirect to the first panel (overview_panel)."""
        response = self.client.get("/insights/")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.endswith("/insights/overview_panel/"))

    def test_dashboard_invalid_panel_redirects(self):
        """Invalid panel ID should redirect to default."""
        response = self.client.get("/insights/non_existent_panel/")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.endswith("/insights/overview_panel/"))

    def test_dashboard_valid_panel_loads(self):
        """Valid panels should load with a 200 OK."""
        response = self.client.get("/insights/package_panel/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "package_panel")

    def test_dashboard_search_package_panel(self):
        """Test CWE search on package panel."""
        PackageV2.objects.create(type="pypi", name="django", version="1.0.0")
        response = self.client.get("/insights/package_panel/?q=pkg:pypi/django")
        self.assertEqual(response.status_code, 200)
        self.assertIn("search_results_dict", response.context)

    def test_dashboard_search_severity_panel(self):
        """Test Severity search on severity panel."""
        PackageV2.objects.create(type="pypi", name="flask", version="1.0.0")
        response = self.client.get("/insights/severity_panel/?q=pkg:pypi/flask")
        self.assertEqual(response.status_code, 200)
        self.assertIn("search_results_dict", response.context)

    def test_dashboard_search_no_results(self):
        """Test search with no matching packages."""
        response = self.client.get("/insights/severity_panel/?q=pkg:pypi/does_not_exist")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["search_error"], "No data available for this query.")
