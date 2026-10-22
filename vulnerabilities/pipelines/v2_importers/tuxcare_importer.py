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

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.osv_v2 import parse_advisory_data_v3


class TuxCareImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    TuxCare Importer Pipeline
    Collect advisories from TuxCare OSV feed.
    """

    pipeline_id = "tuxcare_importer_v2"
    datasource_id = "tuxcare"
    license_url = "https://tuxcare.com/legal"
    spdx_license_expression = "Apache-2.0"
    url = "https://osv-vulnerabilities.storage.googleapis.com/TuxCare/all.zip"
    precedence = 100

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
        with ZipFile(BytesIO(self.advisory_zip)) as zip_file:
            advisory_count = sum(
                1
                for file in zip_file.namelist()
                if file.startswith("CLSA-") and file.endswith(".json")
            )
        return advisory_count

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        """Yield AdvisoryDataV2 using a zipped data dump of OSV data"""
        supported_ecosystems = [
            # els_os
            "rpm",
            "deb",
            # els_lang
            "maven",
            "npm",
            "pypi",
            "composer",
        ]

        with ZipFile(BytesIO(self.advisory_zip)) as zip_file:
            for file_name in zip_file.namelist():
                if not (file_name.startswith("CLSA-") and file_name.endswith(".json")):
                    self.log(
                        f"Unsupported TuxCare advisory data file: {file_name}",
                        level=logging.ERROR,
                    )
                    continue
                with zip_file.open(file_name) as f:
                    advisory_text = f.read()
                    vul_info = json.loads(advisory_text)
                    yield parse_advisory_data_v3(
                        raw_data=vul_info,
                        supported_ecosystems=supported_ecosystems,
                        advisory_url=self.url,
                        advisory_text=advisory_text.decode("utf-8"),
                    )
