#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.pipes.importer import import_advisory
from vulnerabilities.tests import advisory1
from vulnerabilities.tests import get_all_vulnerability_relationships_objects


@pytest.mark.django_db
def test_vulnerability_pipes_importer_import_advisory():
    import_advisory(advisory=advisory1, pipeline_name="test_importer_pipeline")
    all_vulnerability_relation_objects = get_all_vulnerability_relationships_objects()
    import_advisory(advisory=advisory1, pipeline_name="test_importer_pipeline")
    assert all_vulnerability_relation_objects == get_all_vulnerability_relationships_objects()


@pytest.mark.django_db
def test_vulnerability_pipes_importer_import_advisory_different_pipelines():
    import_advisory(advisory=advisory1, pipeline_name="test_importer1_pipeline")
    all_vulnerability_relation_objects = get_all_vulnerability_relationships_objects()
    import_advisory(advisory=advisory1, pipeline_name="test_importer2_pipeline")
    assert all_vulnerability_relation_objects == get_all_vulnerability_relationships_objects()
