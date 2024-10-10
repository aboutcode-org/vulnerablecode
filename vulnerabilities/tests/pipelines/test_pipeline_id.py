#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import importlib
import inspect
import unittest
from pathlib import Path

from vulnerabilities.pipelines import VulnerableCodePipeline

PIPELINE_DIR = Path(__file__).parent.parent.parent / "pipelines"


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.pipeline_dict = self.collect_pipeline_ids()

    def collect_pipeline_ids(self):
        """Return pipeline_ids from all the VulnerableCodePipeline."""
        pipeline_dict = {}

        for pipeline in PIPELINE_DIR.glob("*.py"):
            if pipeline.name == "__init__.py":
                continue

            module_name = pipeline.stem
            module = importlib.import_module(f"vulnerabilities.pipelines.{module_name}")

            for _, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, VulnerableCodePipeline) and obj is not VulnerableCodePipeline:
                    pipeline_id = obj.pipeline_id
                    pipeline_dict[obj] = pipeline_id
                    break

        return pipeline_dict

    def test_no_empty_pipeline_ids(self):
        empty_pipeline_ids = [cls for cls, pid in self.pipeline_dict.items() if pid == ""]

        if empty_pipeline_ids:
            error_messages = [
                f"{cls.__name__} has empty pipeline_id." for cls in empty_pipeline_ids
            ]
            error_message = "`pipeline_id` should not be empty string:\n" + "\n".join(
                error_messages
            )
            assert False, error_message

    def test_no_none_pipeline_ids(self):
        none_pipeline_ids = [cls for cls, pid in self.pipeline_dict.items() if pid == None]

        if none_pipeline_ids:
            error_messages = [f"{cls.__name__} has None pipeline_id." for cls in none_pipeline_ids]
            error_message = "`pipeline_id` should not be None:\n" + "\n".join(error_messages)
            assert False, error_message

    def test_unique_pipeline_ids(self):
        pipeline_ids = self.pipeline_dict.values()
        unique_ids = set(pipeline_ids)
        assert len(pipeline_ids) == len(unique_ids), "`pipeline_id` should be unique."
