#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2


class DummyImporter(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "dummy_importer"
    license_url = "https://example.com/license"
    datasource_id = "dummy_importer"
    spdx_license_expression = "TEST"

    @classmethod
    def steps(cls):
        return (cls.dummy_step,)

    def dummy_step(self):
        pass


class FailingImporter(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "dummy_importer_failing"
    datasource_id = "dummy_importer_failing"
    license_url = "https://example.com/license"
    spdx_license_expression = "TEST"

    @classmethod
    def steps(cls):
        return (cls.dummy_step,)

    def dummy_step(self):
        raise RuntimeError("importer failed")


MOCK_IMPORTERS_REGISTRY = [DummyImporter, FailingImporter]
MOCK_IMPORTERS_REGISTRY = {importer.pipeline_id: importer for importer in MOCK_IMPORTERS_REGISTRY}


@patch("vulnerabilities.importers.IMPORTERS_REGISTRY", MOCK_IMPORTERS_REGISTRY)
class TestImportCommand(TestCase):
    def test_list_sources(self):
        buf = StringIO()
        call_command("import", "--list", stdout=buf)
        out = buf.getvalue()
        assert DummyImporter.pipeline_id in out

    def test_missing_sources(self):
        with pytest.raises(CommandError) as cm:
            call_command("import", stdout=StringIO())

        err = str(cm)
        assert 'Please provide at least one importer to run or use "--all"' in err

    def test_error_message_includes_unknown_sources(self):
        with pytest.raises(CommandError) as cm:
            call_command(
                "import",
                DummyImporter.pipeline_id,
                "foo",
                "bar",
                stdout=StringIO(),
            )

        err = str(cm)
        assert "bar" in err
        assert "foo" in err
        assert DummyImporter.pipeline_id not in err

    def test_import_run(self):
        buf = StringIO()
        call_command("import", DummyImporter.pipeline_id, stdout=buf)
        out = buf.getvalue()
        assert f"Importing data using {DummyImporter.pipeline_id}" in out
        assert f"Successfully imported data using {DummyImporter.pipeline_id}" in out

    def test_bad_importer_fail_error(self):
        buf = StringIO()
        with pytest.raises(CommandError):
            call_command("import", FailingImporter.pipeline_id, stdout=buf)
        out = buf.getvalue()
        assert FailingImporter.pipeline_id in out
