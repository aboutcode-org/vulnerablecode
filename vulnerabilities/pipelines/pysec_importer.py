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
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline


class PyPIImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect advisories from PyPI."""

    pipeline_id = "pysec_importer"

    license_url = "https://github.com/pypa/advisory-database/blob/main/LICENSE"
    url = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
    spdx_license_expression = "CC-BY-4.0"
    importer_name = "PyPI Importer"

    @classmethod
    def steps(cls):
        return (
            cls.fetch_zip,
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
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
        from vulnerabilities.importers.osv import parse_advisory_data

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
                    yield parse_advisory_data(
                        raw_data=vul_info,
                        supported_ecosystems=["pypi"],
                        advisory_url=self.url,
                    )
