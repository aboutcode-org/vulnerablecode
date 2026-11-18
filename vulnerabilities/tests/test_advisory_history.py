from datetime import timedelta

import pytest
from django.utils import timezone

from vulnerabilities.models import AdvisoryHistoryDiff
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.pipelines.v2_improvers.history_diff_backfill import HistoryDiffImproverPipeline


@pytest.mark.django_db
def test_advisory_history_diffing():
    """
    Test the diffing logic for historical advisory snapshots.
    """
    avid1 = "github_osv/GHSA-72hv-8253-57qq"

    severity_high = AdvisorySeverity.objects.create(scoring_system="generic_textual", value="HIGH")
    severity_moderate = AdvisorySeverity.objects.create(
        scoring_system="generic_textual", value="MODERATE"
    )

    old_advisory_snapshot = AdvisoryV2.objects.create(
        advisory_id="GHSA-72hv-8253-57qq",
        unique_content_id="snap1hash",
        date_collected=timezone.now(),
        pipeline_id="test",
        datasource_id="github_osv",
        url="http://test.com",
        avid=avid1,
        summary="Initial summary",
    )
    old_advisory_snapshot.severities.add(severity_high)

    new_advisory_snapshot = AdvisoryV2.objects.create(
        advisory_id="GHSA-72hv-8253-57qq",
        unique_content_id="snap2hash",
        date_collected=timezone.now() + timedelta(days=1),
        pipeline_id="test",
        datasource_id="github_osv",
        url="http://test.com",
        avid=avid1,
        summary="Updated summary",
    )
    new_advisory_snapshot.severities.add(severity_moderate)

    pkg1 = ImpactedPackage.objects.create(
        advisory=old_advisory_snapshot,
        base_purl="pkg:maven/tools.jackson.core/jackson-core",
        affecting_vers="vers:maven/<=2.18.5",
        fixed_vers="vers:maven/2.18.6",
    )
    pkg2 = ImpactedPackage.objects.create(
        advisory=old_advisory_snapshot,
        base_purl="pkg:maven/tools.jackson.core/jackson-core",
        affecting_vers="vers:maven/>=2.19.0|<2.21.1",
        fixed_vers="vers:maven/2.21.1",
    )
    pkg3 = ImpactedPackage.objects.create(
        advisory=old_advisory_snapshot,
        base_purl="pkg:maven/com.fasterxml.jackson.core/jackson-core",
        affecting_vers="vers:maven/>=3.0.0|<3.1.0",
        fixed_vers="vers:maven/3.1.0",
    )

    pipeline = HistoryDiffImproverPipeline()
    pipeline.execute()

    # Run a second time to ensure idempotency
    pipeline.execute()

    old_advisory_snapshot.refresh_from_db()
    new_advisory_snapshot.refresh_from_db()

    assert hasattr(old_advisory_snapshot, "history_diff")
    assert old_advisory_snapshot.history_diff.advisory_before is None

    diff = AdvisoryHistoryDiff.objects.get(advisory_after=new_advisory_snapshot)
    assert diff.summary_removed == "Initial summary"
    assert diff.summary_added == "Updated summary"
    assert severity_moderate in diff.added_severities.all()
    assert severity_high in diff.removed_severities.all()

    assert diff.added_impacted_packages.count() == 0
    assert diff.removed_impacted_packages.count() == 3
    assert pkg1 in diff.removed_impacted_packages.all()
    assert pkg2 in diff.removed_impacted_packages.all()
    assert pkg3 in diff.removed_impacted_packages.all()
    assert AdvisoryHistoryDiff.objects.count() == 2
