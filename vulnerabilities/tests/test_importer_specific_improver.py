#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime

import pytest

from vulnerabilities.importers.nvd import NVDImporter
from vulnerabilities.improve_runner import ImproveRunner
from vulnerabilities.improvers.importer_specific_improver import NVDImprover
from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias


@pytest.mark.django_db
def test_improvement_of_importer_specific_advisories():
    Advisory.objects.create(
        aliases=["CVE-2021-22"],
        summary="TEST",
        created_by=NVDImporter.qualified_name,
        date_collected=datetime.datetime.now(tz=datetime.timezone.utc),
    )
    ImproveRunner(NVDImprover).run()
    alias = Alias.objects.filter(alias="CVE-2021-22").first()
    assert alias is not None
