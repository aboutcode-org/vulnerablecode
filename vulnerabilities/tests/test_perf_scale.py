import os
import time
import random
import pytest

from django.test import RequestFactory, override_settings
from django.db import reset_queries
from django.db import connection
from django.test.utils import CaptureQueriesContext

@pytest.mark.perf
def test_perf_scale_packages(db):
    """Opt-in performance test for package search at scale.

    Disabled by default. Enable by setting environment variable `RUN_PERF=1`.
    Configure scale with `PERF_PACKAGES`, `PERF_VULNS`, `PERF_AFFECTED_PER_VULN` env vars.
    """
    # Running perf test unconditionally as requested.

    # Import models and views here to avoid accessing Django settings during collection
    from vulnerabilities import models
    from vulnerabilities.views import PackageSearch

    PACKAGES = int(os.getenv("PERF_PACKAGES", "2000"))
    VULNS = int(os.getenv("PERF_VULNS", "500"))
    AFFECTED_PER_VULN = int(os.getenv("PERF_AFFECTED_PER_VULN", "10"))
    MAX_SECONDS = float(os.getenv("PERF_MAX_SECONDS", "30"))

    # Bulk-create packages for speed. We compute purl fields so we don't rely on model.save().
    from vulnerabilities import utils

    package_objs = []
    for i in range(PACKAGES):
        purl = f"pkg:maven/org.scale/p{i}@1.0"
        # Use utils.purl_to_dict to get individual fields
        purl_obj = utils.normalize_purl(purl)
        purl_fields = utils.purl_to_dict(purl_obj)
        pkg = models.Package(
            type=purl_fields.get("type", ""),
            namespace=purl_fields.get("namespace", ""),
            name=purl_fields.get("name", ""),
            version=purl_fields.get("version", ""),
            qualifiers=purl_fields.get("qualifiers", ""),
            subpath=purl_fields.get("subpath", ""),
            package_url=str(purl_obj),
            plain_package_url=str(utils.plain_purl(purl_obj)),
        )
        package_objs.append(pkg)

    models.Package.objects.bulk_create(package_objs, batch_size=1000)

    # Fetch created packages
    packages = list(models.Package.objects.filter(package_url__startswith="pkg:maven/org.scale/")
                    .order_by("id"))

    # Bulk-create vulnerabilities
    vuln_objs = [models.Vulnerability(vulnerability_id=f"PV-{j}", summary="perf") for j in range(VULNS)]
    models.Vulnerability.objects.bulk_create(vuln_objs, batch_size=500)
    vulnerabilities = list(models.Vulnerability.objects.filter(vulnerability_id__startswith="PV-")
                          .order_by("vulnerability_id"))

    # Create affected relations deterministically and bulk_insert the through model
    through_model = models.AffectedByPackageRelatedVulnerability
    rel_objs = []
    pkg_count = len(packages)
    for j, v in enumerate(vulnerabilities):
        for k in range(min(AFFECTED_PER_VULN, pkg_count)):
            idx = (j * AFFECTED_PER_VULN + k) % pkg_count
            rel_objs.append(through_model(package=packages[idx], vulnerability=v))

    through_model.objects.bulk_create(rel_objs, batch_size=2000)

    # Measure ordering by affected (descending)
    req = RequestFactory().get("/?search=org.scale&sort=-affected")
    view = PackageSearch()
    view.request = req

    # Measure with explicit query counting
    with override_settings(DEBUG=True):
        reset_queries()
        orig_force_debug = getattr(connection, "force_debug_cursor", False)
        connection.force_debug_cursor = True
        start = time.time()
        try:
            qs = view.get_queryset()
            list(qs[:100])
        finally:
            connection.force_debug_cursor = orig_force_debug
        duration = time.time() - start
        queries_executed = len(connection.queries)

    print(
        f"Perf: packages={PACKAGES} vulns={VULNS} queries={queries_executed} duration={duration:.2f}s"
    )

    # Loose guards to detect regressions; tune as appropriate for your environment.
    assert queries_executed <= 50
    assert duration <= MAX_SECONDS
