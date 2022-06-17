#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import inspect
from unittest.mock import patch

import pytest

from vulnerabilities import importers
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer_yielder import IMPORTERS_REGISTRY

MAX_ADVISORIES = 1


class MaxAdvisoriesCreatedInterrupt(BaseException):
    # Inheriting BaseException is intentional because the function being tested might catch Exception
    pass


@pytest.mark.webtest
@pytest.mark.parametrize(
    ("data_source", "config"),
    ((data["data_source"], data["data_source_cfg"]) for data in IMPORTERS_REGISTRY),
)
def test_updated_advisories(data_source, config):
    if not data_source == "GitHubAPIImporter":
        data_src = getattr(importers, data_source)
        data_src = data_src(batch_size=MAX_ADVISORIES, config=config)
        advisory_counter = 0

        def patched_advisory(*args, **kwargs):
            nonlocal advisory_counter

            if advisory_counter >= MAX_ADVISORIES:
                raise MaxAdvisoriesCreatedInterrupt

            advisory_counter += 1
            return Advisory(*args, **kwargs)

        module = inspect.getmodule(data_src)
        module_members = [m[0] for m in inspect.getmembers(module)]
        advisory_class = f"{module.__name__}.Advisory"
        if "Advisory" not in module_members:
            advisory_class = "vulnerabilities.importer.Advisory"

        # Either
        # 1) Advisory class is successfully patched and MaxAdvisoriesCreatedInterrupt is thrown when
        # 	an importer tries to create an Advisory or
        # 2) Importer somehow bypasses the patch / handles BaseException internally, then
        # 	updated_advisories is required to return non zero advisories
        with patch(advisory_class, side_effect=patched_advisory):
            try:
                with data_src:
                    assert len(list(data_src.updated_advisories())) > 0
            except MaxAdvisoriesCreatedInterrupt:
                pass
