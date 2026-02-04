#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime

import pytest

from vulnerabilities.models import SSVC
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
    pipeline.collect_ssvc_data()

    assert SSVC.objects.filter(source_advisory=vulnrichment_advisory).count() == 1
