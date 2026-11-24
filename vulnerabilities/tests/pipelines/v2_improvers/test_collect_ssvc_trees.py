#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
from datetime import datetime

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext

from vulnerabilities.models import SSVC
from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_importers.vulnrichment_importer import VulnrichImporterPipeline
from vulnerabilities.pipelines.v2_improvers.collect_ssvc_trees import CollectSSVCPipeline
from vulnerabilities.pipelines.v2_improvers.collect_ssvc_trees import (
    convert_vector_to_tree_and_decision,
)
from vulnerabilities.severity_systems import SCORING_SYSTEMS


@pytest.fixture
def ssvc_scoring_system():
    return SCORING_SYSTEMS["ssvc"]


@pytest.fixture
def vulnrichment_advisory(db):
    return AdvisoryV2.objects.create(
        datasource_id=VulnrichImporterPipeline.pipeline_id,
        advisory_id="TEST-2024-0001",
        avid="vulnrichment/TEST-2024-0001",
        url="https://example.com/advisory/TEST-2024-0001",
        unique_content_id="unique-1234",
        date_collected=datetime.now(),
        is_latest=True,
        pipeline_id="ds_importer_v2",
    )


@pytest.fixture
def ssvc_severity(vulnrichment_advisory, ssvc_scoring_system):
    severity = AdvisorySeverity.objects.create(
        scoring_system=ssvc_scoring_system,
        scoring_elements="SSVCv2/E:A/A:Y/T:T/P:E/B:I/M:H/D:C",
    )
    vulnrichment_advisory.severities.add(severity)
    vulnrichment_advisory.save()
    return severity


@pytest.fixture
def related_advisory(db):
    return AdvisoryV2.objects.create(
        datasource_id="other_importer",
        advisory_id="TEST-2024-0001",
        avid="other/TEST-2024-0001",
        url="https://example.com/related/TEST-2024-0001",
        unique_content_id="unique-5678",
        date_collected=datetime.now(),
        is_latest=True,
        pipeline_id="ds_importer_v2",
    )


def test_convert_vector_valid():
    vector = "SSVCv2/E:A/A:Y/T:T/P:E/B:I/M:H/D:C"

    tree, decision = convert_vector_to_tree_and_decision(vector)

    assert decision == "Act"

    assert tree == [
        {"Exploitation": "active"},
        {"Automatable": "yes"},
        {"Technical Impact": "total"},
        {"Mission Prevalence": "essential"},
        {"Public Well-being Impact": "irreversible"},
        {"Mission & Well-being": "high"},
    ]


def test_convert_vector_missing_decision():
    vector = "SSVCv2/E:N/A:N/T:P/P:M/B:M/M:L"

    tree, decision = convert_vector_to_tree_and_decision(vector)

    assert decision is None
    assert len(tree) == 6


def test_convert_vector_invalid_prefix():
    with pytest.raises(ValueError):
        convert_vector_to_tree_and_decision("INVALID/E:A/D:C")


def test_convert_vector_unknown_keys_ignored():
    vector = "SSVCv2/E:A/X:Z/D:T"

    tree, decision = convert_vector_to_tree_and_decision(vector)

    assert decision == "Track"
    assert tree == [{"Exploitation": "active"}]


@pytest.mark.django_db
def test_collect_ssvc_creates_ssvc_object(
    vulnrichment_advisory,
    ssvc_severity,
):
    pipeline = CollectSSVCPipeline()

    pipeline.collect_ssvc_data()

    ssvc_qs = SSVC.objects.filter(source_advisory=vulnrichment_advisory)

    assert ssvc_qs.count() == 1

    ssvc = ssvc_qs.first()
    assert ssvc.decision == "Act"
    assert ssvc.vector == ssvc_severity.scoring_elements
    assert isinstance(ssvc.options, list)
    assert len(ssvc.options) == 6


@pytest.mark.django_db
def test_collect_ssvc_links_related_advisories(
    vulnrichment_advisory,
    ssvc_severity,
    related_advisory,
):
    pipeline = CollectSSVCPipeline()
    pipeline.collect_ssvc_data()

    ssvc = SSVC.objects.get(source_advisory=vulnrichment_advisory)

    related_ids = list(ssvc.related_advisories.values_list("id", flat=True))

    assert related_advisory.id in related_ids
    assert vulnrichment_advisory.id not in related_ids


@pytest.mark.django_db
def test_collect_ssvc_idempotent(
    vulnrichment_advisory,
    ssvc_severity,
):
    pipeline = CollectSSVCPipeline()

    pipeline.collect_ssvc_data()
    with CaptureQueriesContext(connection) as ctx:
        pipeline.collect_ssvc_data()

    assert SSVC.objects.filter(source_advisory=vulnrichment_advisory).count() == 1
    assert not any(q["sql"].lstrip().upper().startswith("UPDATE") for q in ctx.captured_queries)


@pytest.mark.django_db
def test_collect_ssvc_links_direct_and_alias_related_advisories(
    vulnrichment_advisory,
    ssvc_severity,
    related_advisory,
):
    alias_related = AdvisoryV2.objects.create(
        datasource_id="ghsa",
        advisory_id="GHSA-1111-2222-3333",
        avid="ghsa/GHSA-1111-2222-3333",
        url="https://example.com/ghsa/GHSA-1111-2222-3333",
        unique_content_id="unique-alias-match",
        is_latest=True,
        pipeline_id="github_importer_v2",
    )
    alias_obj = AdvisoryAlias.objects.create(alias=vulnrichment_advisory.advisory_id)
    alias_related.aliases.add(alias_obj)

    unrelated = AdvisoryV2.objects.create(
        datasource_id="nvd",
        advisory_id="CVE-2024-9999",
        avid="nvd/CVE-2024-9999",
        url="https://example.com/nvd/CVE-2024-9999",
        unique_content_id="unique-unrelated",
        is_latest=True,
        pipeline_id="nvd_importer_v2",
    )
    unrelated.aliases.add(AdvisoryAlias.objects.create(alias="GHSA-9999-9999-9999"))

    pipeline = CollectSSVCPipeline()
    pipeline.collect_ssvc_data()

    ssvc = SSVC.objects.get(source_advisory=vulnrichment_advisory)
    related_ids = set(ssvc.related_advisories.values_list("id", flat=True))

    assert related_ids == {related_advisory.id, alias_related.id}
    assert vulnrichment_advisory.id not in related_ids
    assert unrelated.id not in related_ids


@pytest.mark.django_db
def test_collect_ssvc_updates_existing_ssvc_row(
    vulnrichment_advisory,
    ssvc_severity,
    related_advisory,
):
    existing = SSVC.objects.create(
        source_advisory=vulnrichment_advisory,
        vector=ssvc_severity.scoring_elements,
        options=[],
        decision="Track",
    )

    pipeline = CollectSSVCPipeline()
    pipeline.collect_ssvc_data()

    existing.refresh_from_db()
    assert SSVC.objects.filter(source_advisory=vulnrichment_advisory).count() == 1
    assert existing.decision == "Act"
    assert len(existing.options) == 6
    assert set(existing.related_advisories.values_list("id", flat=True)) == {related_advisory.id}


@pytest.mark.django_db
def test_collect_ssvc_batched_queries_and_no_unbounded_prefetch(ssvc_scoring_system):
    vector = "SSVCv2/E:A/A:Y/T:T/P:E/B:I/M:H/D:C"
    expected_links = {}

    for i in range(5):
        cve_id = f"CVE-2024-200{i}"
        source = AdvisoryV2.objects.create(
            datasource_id=VulnrichImporterPipeline.pipeline_id,
            advisory_id=cve_id,
            avid=f"vulnrichment/{cve_id}",
            url="https://example.com/vulnrichment/" + cve_id,
            unique_content_id=f"src-{i}",
            is_latest=True,
            pipeline_id="vulnrichment_importer_v2",
        )
        sev = AdvisorySeverity.objects.create(
            scoring_system=ssvc_scoring_system,
            scoring_elements=vector,
        )
        source.severities.add(sev)

        direct_rel = AdvisoryV2.objects.create(
            datasource_id="nvd",
            advisory_id=cve_id,
            avid=f"nvd/{cve_id}",
            url="https://example.com/nvd/" + cve_id,
            unique_content_id=f"nvd-{i}",
            is_latest=True,
            pipeline_id="nvd_importer_v2",
        )

        alias_rel = AdvisoryV2.objects.create(
            datasource_id="ghsa",
            advisory_id=f"GHSA-0000-0000-000{i}",
            avid=f"ghsa/GHSA-0000-0000-000{i}",
            url="https://example.com/ghsa/" + str(i),
            unique_content_id=f"ghsa-{i}",
            is_latest=True,
            pipeline_id="github_importer_v2",
        )
        alias_rel.aliases.add(AdvisoryAlias.objects.create(alias=cve_id))

        expected_links[source.id] = {direct_rel.id, alias_rel.id}

    pipeline = CollectSSVCPipeline()
    pipeline.batch_size = 2
    pipeline.through_batch_size = 3

    with CaptureQueriesContext(connection) as ctx:
        pipeline.collect_ssvc_data()

    assert SSVC.objects.count() == 5
    for source_id, expected_related_ids in expected_links.items():
        ssvc = SSVC.objects.get(source_advisory_id=source_id)
        actual_related_ids = set(ssvc.related_advisories.values_list("id", flat=True))
        assert actual_related_ids == expected_related_ids

    sql_statements = [q["sql"] for q in ctx.captured_queries]

    for sql in sql_statements:
        for match in re.finditer(r"\bIN\s*\(([^)]+)\)", sql, flags=re.IGNORECASE):
            items = [item.strip() for item in match.group(1).split(",") if item.strip()]
            assert len(items) <= pipeline.batch_size, f"Unbounded IN clause ({len(items)}): {sql}"

    alias_through_table = AdvisoryV2.aliases.through._meta.db_table
    alias_queries = [sql for sql in sql_statements if alias_through_table in sql]
    assert len(alias_queries) == 3
    assert not any(
        re.search(r"advisoryv2_id\W+IN\s*\(", sql, flags=re.IGNORECASE) for sql in alias_queries
    )

    ssvc_through_table = SSVC.related_advisories.through._meta.db_table
    through_inserts = [
        sql
        for sql in sql_statements
        if sql.lstrip().upper().startswith("INSERT") and ssvc_through_table in sql
    ]
    # Batches yield 4, 4, and 2 through rows -> 2 + 2 + 1 = 5 inserts at through_batch_size=3.
    assert len(through_inserts) == 5


@pytest.mark.django_db
def test_collect_ssvc_empty_dataset_skips_batch_queries():
    pipeline = CollectSSVCPipeline()

    with CaptureQueriesContext(connection) as ctx:
        pipeline.collect_ssvc_data()

    assert SSVC.objects.count() == 0
    assert len(ctx.captured_queries) == 1


@pytest.mark.django_db
def test_collect_ssvc_deduplicates_identical_vectors_and_skips_invalid(
    vulnrichment_advisory,
    ssvc_severity,
    ssvc_scoring_system,
):
    duplicate_severity = AdvisorySeverity.objects.create(
        scoring_system=ssvc_scoring_system,
        scoring_elements=ssvc_severity.scoring_elements,
        url="https://example.com/duplicate-severity",
    )
    invalid_severity = AdvisorySeverity.objects.create(
        scoring_system=ssvc_scoring_system,
        scoring_elements="INVALID/E:A/D:C",
    )
    vulnrichment_advisory.severities.add(duplicate_severity, invalid_severity)

    non_latest = AdvisoryV2.objects.create(
        datasource_id=VulnrichImporterPipeline.pipeline_id,
        advisory_id="TEST-2024-OLD",
        avid="vulnrichment/TEST-2024-OLD",
        url="https://example.com/advisory/TEST-2024-OLD",
        unique_content_id="unique-old",
        is_latest=False,
        pipeline_id="ds_importer_v2",
    )
    non_latest.severities.add(ssvc_severity)

    pipeline = CollectSSVCPipeline()
    pipeline.collect_ssvc_data()

    assert SSVC.objects.filter(source_advisory=vulnrichment_advisory).count() == 1
    assert SSVC.objects.filter(source_advisory=non_latest).count() == 0
