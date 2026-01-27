import pytest
from django.test import RequestFactory
from django.db import connection
from django.test.utils import CaptureQueriesContext

from vulnerabilities import models
from vulnerabilities.views import PackageSearch, VulnerabilitySearch


@pytest.fixture
def rf():
    return RequestFactory()


@pytest.fixture
def seeded_data(db):
    """Create packages and vulnerabilities used by tests.

    Returns a dict with keys: p1, p2, p3, v1, v2
    """
    p1, _ = models.Package.objects.get_or_create_from_purl("pkg:maven/org.test/a@1.0")
    p2, _ = models.Package.objects.get_or_create_from_purl("pkg:maven/org.test/b@1.0")
    p3, _ = models.Package.objects.get_or_create_from_purl("pkg:maven/org.test/c@1.0")

    v1 = models.Vulnerability.objects.create(vulnerability_id="V-1", summary="v1")
    v2 = models.Vulnerability.objects.create(vulnerability_id="V-2", summary="v2")

    models.AffectedByPackageRelatedVulnerability.objects.create(package=p1, vulnerability=v1)
    models.AffectedByPackageRelatedVulnerability.objects.create(package=p2, vulnerability=v1)
    models.AffectedByPackageRelatedVulnerability.objects.create(package=p3, vulnerability=v2)

    models.FixingPackageRelatedVulnerability.objects.create(package=p3, vulnerability=v1)

    return {"p1": p1, "p2": p2, "p3": p3, "v1": v1, "v2": v2}


def test_package_search_sort_by_affected_and_query_count(rf, seeded_data):
    # Ascending (search for package fragment so .search() returns results)
    req_asc = rf.get("/?search=org.test&sort=affected")
    view = PackageSearch()
    view.request = req_asc

    with CaptureQueriesContext(connection) as ctx:
        qs_asc = view.get_queryset()
        vals_asc = list(qs_asc.values_list("vulnerability_count", flat=True))

    assert all(isinstance(v, int) for v in vals_asc)
    assert vals_asc == sorted(vals_asc)
    # Bound the number of DB queries for the get_queryset call.
    assert len(ctx) <= 6

    # Descending
    req_desc = rf.get("/?search=org.test&sort=-affected")
    view_desc = PackageSearch()
    view_desc.request = req_desc
    qs_desc = view_desc.get_queryset()
    vals_desc = list(qs_desc.values_list("vulnerability_count", flat=True))
    assert vals_desc == sorted(vals_desc, reverse=True)

    purls_asc = list(qs_asc.values_list("package_url", flat=True))
    purls_desc = list(qs_desc.values_list("package_url", flat=True))
    assert set(purls_asc) == set(purls_desc)


def test_vulnerability_search_sort_by_affected(rf, seeded_data):
    # Ascending: V-2 (1) then V-1 (2)
    req_asc = rf.get("/?search=V&sort=affected")
    view = VulnerabilitySearch()
    view.request = req_asc
    qs_asc = view.get_queryset()
    vuln_ids_asc = list(qs_asc.values_list("vulnerability_id", flat=True))
    assert vuln_ids_asc == ["V-2", "V-1"]

    # Descending: V-1 then V-2
    req_desc = rf.get("/?search=V&sort=-affected")
    view_desc = VulnerabilitySearch()
    view_desc.request = req_desc
    qs_desc = view_desc.get_queryset()
    vuln_ids_desc = list(qs_desc.values_list("vulnerability_id", flat=True))
    assert vuln_ids_desc == ["V-1", "V-2"]


def test_package_search_basic_search(rf, seeded_data):
    req = rf.get("/?search=org.test")
    view = PackageSearch()
    view.request = req
    qs = view.get_queryset()
    purls = list(qs.values_list("package_url", flat=True))

    expected = [seeded_data["p1"].package_url, seeded_data["p2"].package_url, seeded_data["p3"].package_url]
    assert set(purls) == set(expected)


def test_vulnerability_search_basic_search(rf, seeded_data):
    req = rf.get("/?search=V")
    view = VulnerabilitySearch()
    view.request = req
    qs = view.get_queryset()
    vuln_ids = list(qs.values_list("vulnerability_id", flat=True))

    assert set(vuln_ids) == {"V-1", "V-2"}