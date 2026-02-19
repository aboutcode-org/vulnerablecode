#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_improvers.relate_severities import RelateSeveritiesPipeline
from vulnerabilities.severity_systems import EPSS


@pytest.mark.django_db
def test_relate_severities_by_advisory_id():
    base = AdvisoryV2.objects.create(
        advisory_id="CVE-2024-0001",
        datasource_id="nvd",
        avid="nvd/CVE-2024-0001",
        unique_content_id="ab1",
        url="https://example.com/advisory/CVE-2024-0001",
        date_collected="2024-01-01",
    )

    severity_advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2024-0001",
        datasource_id="epss_importer_v2",
        avid="epss/CVE-2024-0001",
        unique_content_id="ab2",
        url="https://example.com/epss/CVE-2024-0001",
        date_collected="2024-01-02",
    )
    severity_advisory.severities.create(
        scoring_system=EPSS.identifier,
        value="0.5",
    )

    pipeline = RelateSeveritiesPipeline()
    pipeline.relate_severities()

    assert base.related_advisory_severities.filter(id=severity_advisory.id).exists()


@pytest.mark.django_db
def test_relate_severities_via_alias():
    base = AdvisoryV2.objects.create(
        advisory_id="CVE-2024-0002",
        datasource_id="nvd",
        avid="nvd/CVE-2024-0002",
        unique_content_id="ab3",
        url="https://example.com/advisory/CVE-2024-0002",
        date_collected="2024-01-01",
    )

    base.aliases.create(alias="CVE-2024-ALIAS")

    severity_advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2024-ALIAS",
        datasource_id="epss_importer_v2",
        avid="epss/CVE-2024-ALIAS",
        unique_content_id="ab4",
        url="https://example.com/epss/CVE-2024-ALIAS",
        date_collected="2024-01-02",
    )
    severity_advisory.severities.create(
        scoring_system=EPSS.identifier,
        value="0.8",
    )

    pipeline = RelateSeveritiesPipeline()
    pipeline.relate_severities()

    assert base.related_advisory_severities.filter(id=severity_advisory.id).exists()


@pytest.mark.django_db
def test_no_self_relation_created():
    advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2024-0003",
        datasource_id="epss_importer_v2",
        unique_content_id="ab5",
        url="https://example.com/advisory/CVE-2024-0003",
        date_collected="2024-01-03",
        avid="epss/CVE-2024-0003",
    )
    advisory.severities.create(
        scoring_system=EPSS.identifier,
        value="0.2",
    )

    pipeline = RelateSeveritiesPipeline()
    pipeline.relate_severities()

    assert not advisory.related_advisory_severities.filter(id=advisory.id).exists()


@pytest.mark.django_db
def test_unsupported_severity_system_is_ignored():
    base = AdvisoryV2.objects.create(
        advisory_id="CVE-2024-0004",
        datasource_id="nvd",
        unique_content_id="ab6",
        url="https://example.com/advisory/CVE-2024-0004",
        date_collected="2024-01-01",
        avid="nvd/CVE-2024-0004",
    )

    severity_advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2024-0004",
        datasource_id="epss_importer_v2",
        unique_content_id="ab7",
        url="https://example.com/epss/CVE-2024-0004",
        date_collected="2024-01-02",
        avid="epss/CVE-2024-0004",
    )
    severity_advisory.severities.create(
        scoring_system="UNKNOWN_SYSTEM",
        value="9.9",
    )

    pipeline = RelateSeveritiesPipeline()
    pipeline.relate_severities()

    assert base.related_advisory_severities.count() == 0


@pytest.mark.django_db
def test_pipeline_is_idempotent():
    base = AdvisoryV2.objects.create(
        advisory_id="CVE-2024-0005",
        datasource_id="nvd",
        unique_content_id="ab8",
        url="https://example.com/advisory/CVE-2024-0005",
        date_collected="2024-01-01",
        avid="nvd/CVE-2024-0005",
    )

    severity = AdvisoryV2.objects.create(
        advisory_id="CVE-2024-0005",
        datasource_id="epss_importer_v2",
        unique_content_id="ab9",
        url="https://example.com/epss/CVE-2024-0005",
        date_collected="2024-01-02",
        avid="epss/CVE-2024-0005",
    )
    severity.severities.create(
        scoring_system=EPSS.identifier,
        value="0.9",
    )

    pipeline = RelateSeveritiesPipeline()

    pipeline.relate_severities()
    pipeline.relate_severities()

    assert base.related_advisory_severities.count() == 1
