from django.test import TestCase

from insights.charts.importer_panel import exploits_queryset
from insights.charts.importer_panel import packages_queryset
from vulnerabilities.models import AdvisoryExploit
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import ImpactedPackageAffecting
from vulnerabilities.models import PackageV2


def create_adv(avid, unique_id):
    return AdvisoryV2.objects.create(
        avid=f"github_osv/{avid}",
        datasource_id="github_osv",
        unique_content_id=unique_id,
        is_latest=True,
        pipeline_id="github_osv_pipeline",
        advisory_id=avid,
        url="https://example.com/" + avid,
    )


class TestImporterPanelQuerysets(TestCase):
    def test_packages_queryset(self):
        advisory_with_package = create_adv("GHSA-1", "1")
        pkg1 = PackageV2.objects.create(type="npm", name="test1", version="1.0.0")
        impact1 = ImpactedPackage.objects.create(advisory=advisory_with_package)
        ImpactedPackageAffecting.objects.create(impacted_package=impact1, package=pkg1)

        advisory_with_ghost_package = create_adv("GHSA-2", "2")
        pkg2 = PackageV2.objects.create(type="npm", name="test2", version="2.0.0", is_ghost=True)
        impact2 = ImpactedPackage.objects.create(advisory=advisory_with_ghost_package)
        ImpactedPackageAffecting.objects.create(impacted_package=impact2, package=pkg2)

        advisory_without_package = create_adv("GHSA-3", "3")

        qs = list(packages_queryset())

        self.assertEqual(len(qs), 1)
        stats = qs[0]
        self.assertEqual(stats["datasource_id"], "github_osv")
        self.assertEqual(stats["total_advisories"], 3)
        self.assertEqual(stats["advisories_with_packages"], 2)  # First two have packages
        self.assertEqual(stats["advisories_with_ghost_packages"], 1)

    def test_exploits_queryset(self):
        advisory_with_kev = create_adv("GHSA-1", "1")
        AdvisoryExploit.objects.create(advisory=advisory_with_kev, data_source="KEV")

        advisory_with_metasploit = create_adv("GHSA-2", "2")
        AdvisoryExploit.objects.create(advisory=advisory_with_metasploit, data_source="Metasploit")

        advisory_with_exploitdb = create_adv("GHSA-3", "3")
        AdvisoryExploit.objects.create(advisory=advisory_with_exploitdb, data_source="Exploit-DB")

        advisory_without_exploits = create_adv("GHSA-4", "4")

        qs = list(exploits_queryset())

        self.assertEqual(len(qs), 1)
        stats = qs[0]
        self.assertEqual(stats["datasource_id"], "github_osv")

        # GHSA-4 shouldn't count in these
        self.assertEqual(stats["advisories_with_kev"], 1)
        self.assertEqual(stats["advisories_with_metasploit"], 1)
        self.assertEqual(stats["advisories_with_exploitdb"], 1)
