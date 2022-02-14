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

from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory


class DummyImprover(Improver):
    @property
    def interesting_advisories(self):
        return Advisory.objects.none()

    def get_inferences(self):
        return []


MOCK_IMPROVERS_REGISTRY = [DummyImprover]
MOCK_IMPROVERS_REGISTRY = {
    improver.qualified_name: improver for improver in MOCK_IMPROVERS_REGISTRY
}


@patch("vulnerabilities.improvers.IMPROVERS_REGISTRY", MOCK_IMPROVERS_REGISTRY)
class TestImproveCommand(TestCase):
    def test_list_sources(self):
        buf = StringIO()
        call_command("improve", "--list", stdout=buf)
        out = buf.getvalue()
        assert DummyImprover.qualified_name in out

    def test_missing_sources(self):
        with pytest.raises(CommandError) as cm:
            call_command("improve", stdout=StringIO())

        err = str(cm)
        assert 'Please provide at least one improver to run or use "--all"' in err

    def test_error_message_includes_unknown_sources(self):
        with pytest.raises(CommandError) as cm:
            call_command(
                "improve",
                DummyImprover.qualified_name,
                "foo",
                "bar",
                stdout=StringIO(),
            )

        err = str(cm)
        assert "bar" in err
        assert "foo" in err
        assert DummyImprover.qualified_name not in err

    def test_improve_run(self):
        buf = StringIO()
        call_command("improve", DummyImprover.qualified_name, stdout=buf)
        out = buf.getvalue()
        assert "Successfully improved data using" in out
