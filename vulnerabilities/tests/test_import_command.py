# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from vulnerabilities.importer import AdvisoryData
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
