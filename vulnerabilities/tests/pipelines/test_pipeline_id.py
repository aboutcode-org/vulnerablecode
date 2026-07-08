#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import collections
import importlib
import inspect
import unittest
from pathlib import Path

from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipelines import VulnerableCodePipeline

PIPELINE_DIR = Path(__file__).parent.parent.parent / "pipelines"


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.pipeline_dict = self.collect_pipeline_ids()
        self.v2_pipeline_dict = self.collect_v2_pipeline_ids()

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

    def import_all_pipeline_modules(self):
        """Import all modules under vulnerabilities.pipelines recursively."""
        for pipeline in PIPELINE_DIR.rglob("*.py"):
            if pipeline.name == "__init__.py":
                continue

            module_name = ".".join(pipeline.relative_to(PIPELINE_DIR).with_suffix("").parts)
            importlib.import_module(f"vulnerabilities.pipelines.{module_name}")

    def collect_v2_pipeline_ids(self):
        """Return pipeline_id and datasource_id from all VulnerableCodeBaseImporterPipelineV2 subclasses."""
        self.import_all_pipeline_modules()
        importlib.import_module("vulnerabilities.pipes.vcs_collector_utils")

        pipeline_dict = {}
        for obj in self._all_subclasses(VulnerableCodeBaseImporterPipelineV2):
            pipeline_dict[obj] = (obj.pipeline_id, obj.datasource_id)

        return pipeline_dict

    def _all_subclasses(self, cls):
        subclasses = set(cls.__subclasses__())
        for subclass in list(subclasses):
            subclasses.update(self._all_subclasses(subclass))
        return subclasses

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

    def test_v2_pipeline_ids_are_defined(self):
        missing_pipeline_ids = [
            cls.__name__
            for cls, (pipeline_id, _) in self.v2_pipeline_dict.items()
            if pipeline_id is None or pipeline_id == ""
        ]

        if missing_pipeline_ids:
            error_messages = [
                f"{pipeline} has missing pipeline_id." for pipeline in missing_pipeline_ids
            ]
            error_message = (
                "`pipeline_id` for V2 pipelines must be defined and non-empty:\n"
                + "\n".join(error_messages)
            )
            assert False, error_message

    def test_v2_datasource_ids_are_defined(self):
        missing_datasource_ids = [
            cls.__name__
            for cls, (_, datasource_id) in self.v2_pipeline_dict.items()
            if datasource_id is None or datasource_id == ""
        ]

        if missing_datasource_ids:
            error_messages = [
                f"{pipeline} has missing datasource_id." for pipeline in missing_datasource_ids
            ]
            error_message = (
                "`datasource_id` for V2 pipelines must be defined and non-empty:\n"
                + "\n".join(error_messages)
            )
            assert False, error_message

    def test_unique_v2_pipeline_ids(self):
        pipeline_to_classes = collections.defaultdict(list)
        for cls, (pipeline_id, _) in self.v2_pipeline_dict.items():
            pipeline_to_classes[pipeline_id].append(cls.__name__)

        duplicates = {
            pipeline_id: classes
            for pipeline_id, classes in pipeline_to_classes.items()
            if pipeline_id and len(classes) > 1
        }

        assert not duplicates, "Duplicate V2 pipeline_id values found: " + ", ".join(
            f"{pipeline_id}: {classes}" for pipeline_id, classes in duplicates.items()
        )

    def test_unique_v2_datasource_ids(self):
        datasource_to_classes = collections.defaultdict(list)
        for cls, (_, datasource_id) in self.v2_pipeline_dict.items():
            datasource_to_classes[datasource_id].append(cls.__name__)

        duplicates = {
            datasource_id: classes
            for datasource_id, classes in datasource_to_classes.items()
            if datasource_id and len(classes) > 1
        }

        assert not duplicates, "Duplicate V2 datasource_id values found: " + ", ".join(
            f"{datasource_id}: {classes}" for datasource_id, classes in duplicates.items()
        )
