#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from vulnerabilities.importer import Importer


class DummyImporter(Importer):
    spdx_license_expression = "dummy license"

    def advisory_data(self):
        return []


class UnLicensedImporter(Importer):
    def advisory_data(self):
        return []


MOCK_IMPORTERS_REGISTRY = [DummyImporter, UnLicensedImporter]
MOCK_IMPORTERS_REGISTRY = {
    importer.qualified_name: importer for importer in MOCK_IMPORTERS_REGISTRY
}


@patch("vulnerabilities.importers.IMPORTERS_REGISTRY", MOCK_IMPORTERS_REGISTRY)
class TestImportCommand(TestCase):
    def test_list_sources(self):
        buf = StringIO()
        call_command("import", "--list", stdout=buf)
        out = buf.getvalue()
        assert DummyImporter.qualified_name in out

    def test_missing_sources(self):
        with pytest.raises(CommandError) as cm:
            call_command("import", stdout=StringIO())

        err = str(cm)
        assert 'Please provide at least one importer to run or use "--all"' in err

    def test_error_message_includes_unknown_sources(self):
        with pytest.raises(CommandError) as cm:
            call_command(
                "import",
                DummyImporter.qualified_name,
                "foo",
                "bar",
                stdout=StringIO(),
            )

        err = str(cm)
        assert "bar" in err
        assert "foo" in err
        assert DummyImporter.qualified_name not in err

    def test_import_run(self):
        buf = StringIO()
        call_command("import", DummyImporter.qualified_name, stdout=buf)
        out = buf.getvalue()
        assert "Successfully imported data using" in out

    def test_bad_importer_fail_error(self):
        buf = StringIO()
        with pytest.raises(CommandError):
            call_command("import", UnLicensedImporter.qualified_name, stdout=buf)
        out = buf.getvalue()
        assert "Failed to run importer" in out
