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

from vulnerabilities.pipelines import VulnerableCodePipeline


class DummyImprover(VulnerableCodePipeline):
    pipeline_id = "dummy_improver"
    license_expression = None

    @classmethod
    def steps(cls):
        return (cls.dummy_step,)

    def dummy_step(self):
        pass


MOCK_IMPROVERS_REGISTRY = [DummyImprover]
MOCK_IMPROVERS_REGISTRY = {improver.pipeline_id: improver for improver in MOCK_IMPROVERS_REGISTRY}


@patch("vulnerabilities.improvers.IMPROVERS_REGISTRY", MOCK_IMPROVERS_REGISTRY)
class TestImproveCommand(TestCase):
    def test_list_sources(self):
        buf = StringIO()
        call_command("improve", "--list", stdout=buf)
        out = buf.getvalue()
        assert DummyImprover.pipeline_id in out

    def test_missing_sources(self):
        with pytest.raises(CommandError) as cm:
            call_command("improve", stdout=StringIO())

        err = str(cm)
        assert 'Please provide at least one improver to run or use "--all"' in err

    def test_error_message_includes_unknown_sources(self):
        with pytest.raises(CommandError) as cm:
            call_command(
                "improve",
                DummyImprover.pipeline_id,
                "foo",
                "bar",
                stdout=StringIO(),
            )

        err = str(cm)
        assert "bar" in err
        assert "foo" in err
        assert DummyImprover.pipeline_id not in err

    def test_improve_run(self):
        buf = StringIO()
        call_command("improve", DummyImprover.pipeline_id, stdout=buf)
        out = buf.getvalue()
        assert "Successfully improved data using" in out
