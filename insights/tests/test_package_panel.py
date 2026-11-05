from django.test import TestCase

from insights.charts.package_panel import ecosystem_distribution_queryset
from insights.charts.package_panel import top_packages_queryset
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import ImpactedPackageAffecting
from vulnerabilities.models import PackageV2


class TestPackagePanelQuerysets(TestCase):
    def test_ecosystem_distribution_queryset(self):
        PackageV2.objects.create(type="npm", name="test1", version="1.0.0")
        PackageV2.objects.create(type="npm", name="test2", version="1.0.0")
        PackageV2.objects.create(type="pypi", name="test3", version="1.0.0")
        PackageV2.objects.create(type="gem", name="test4", version="1.0.0")

        tracked_types = ["npm", "pypi"]

        qs = list(ecosystem_distribution_queryset(tracked_types))
        stats = {item["type"]: item["total_package_count"] for item in qs}

        self.assertEqual(len(stats), 2)  # gem should be excluded
        self.assertEqual(stats["npm"], 2)
        self.assertEqual(stats["pypi"], 1)

    def test_top_packages_queryset(self):
        django_v1 = PackageV2.objects.create(type="pypi", name="django", version="1.0.0")
        django_v2 = PackageV2.objects.create(type="pypi", name="django", version="2.0.0")
        flask_v1 = PackageV2.objects.create(type="pypi", name="flask", version="1.0.0")

        def create_impact(advisory_id, package):
            adv = AdvisoryV2.objects.create(
                avid=f"github_osv/{advisory_id}",
                datasource_id="github_osv",
                unique_content_id=advisory_id,
                is_latest=True,
                pipeline_id="github_osv_pipeline",
                advisory_id=advisory_id,
                url=f"https://github.com/advisories/{advisory_id}",
            )
            impact = ImpactedPackage.objects.create(advisory=adv)
            ImpactedPackageAffecting.objects.create(impacted_package=impact, package=package)

        create_impact("GHSA-1111", django_v1)
        create_impact("GHSA-2222", django_v2)
        create_impact("GHSA-3333", django_v2)
        create_impact("GHSA-4444", flask_v1)

        qs = list(top_packages_queryset("pypi"))

        self.assertEqual(len(qs), 2)
        self.assertEqual(qs[0]["name"], "django")
        self.assertEqual(qs[0]["count"], 3)
        self.assertEqual(qs[1]["name"], "flask")
        self.assertEqual(qs[1]["count"], 1)
