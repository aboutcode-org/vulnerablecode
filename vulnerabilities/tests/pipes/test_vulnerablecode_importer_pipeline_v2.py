#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timedelta

import pytest

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2


class DummyImporter(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "dummy"
    log_messages = []

    def log(self, message, level=logging.INFO):
        self.log_messages.append((level, message))

    def collect_advisories(self):
        yield from self._advisories

    def advisories_count(self):
        return len(self._advisories)


@pytest.fixture
def dummy_advisory():
    return AdvisoryData(
        summary="Test advisory",
        aliases=["CVE-2025-0001"],
        references_v2=[],
        severities=[],
        weaknesses=[],
        affected_packages=[],
        advisory_id="ADV-123",
        date_published=datetime.now() - timedelta(days=10),
        url="https://example.com/advisory/1",
    )


@pytest.fixture
def dummy_importer(dummy_advisory):
    importer = DummyImporter()
    importer._advisories = [dummy_advisory]
    return importer


@pytest.mark.django_db
def test_collect_and_store_advisories(dummy_importer):
    dummy_importer.collect_and_store_advisories()
    assert len(dummy_importer.log_messages) >= 2
    assert "Successfully collected" in dummy_importer.log_messages[-1][1]
    assert AdvisoryV2.objects.count() == 1
