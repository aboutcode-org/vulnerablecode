#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import logging
from io import BytesIO
from typing import Iterable
from zipfile import ZipFile

import requests

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2


class PyPIImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    PyPI Importer Pipeline

    Collect advisories from PyPI."""

    pipeline_id = "pysec_importer_v2"
    license_url = "https://github.com/pypa/advisory-database/blob/main/LICENSE"
    url = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
    spdx_license_expression = "CC-BY-4.0"

    @classmethod
    def steps(cls):
        return (
            cls.fetch_zip,
            cls.collect_and_store_advisories,
        )

    def fetch_zip(self):
        self.log(f"Fetching `{self.url}`")
        self.advisory_zip = requests.get(self.url).content

    def advisories_count(self) -> int:
        with ZipFile(BytesIO(self.advisory_zip)) as zip:
            advisory_count = sum(1 for file in zip.namelist() if file.startswith("PYSEC-"))
        return advisory_count

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        """Yield AdvisoryData using a zipped data dump of OSV data"""
        from vulnerabilities.importers.osv import parse_advisory_data_v2

        with ZipFile(BytesIO(self.advisory_zip)) as zip_file:
            for file_name in zip_file.namelist():
                if not file_name.startswith("PYSEC-"):
                    self.log(
                        f"Unsupported PyPI advisory data file: {file_name}",
                        level=logging.ERROR,
                    )
                    continue
                with zip_file.open(file_name) as f:
                    vul_info = json.load(f)
                    advisory_text = f.read()
                    yield parse_advisory_data_v2(
                        raw_data=vul_info,
                        supported_ecosystems=["pypi"],
                        advisory_url=self.url,
                        advisory_text=advisory_text.decode("utf-8"),
                    )
