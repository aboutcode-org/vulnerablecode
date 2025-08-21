#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#

from io import BytesIO
from typing import Iterable
from zipfile import ZipFile

from packageurl import PackageURL
from univers.versions import PypiVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.pysec_importer import PyPIImporterPipeline


class PySecLiveImporterPipeline(PyPIImporterPipeline):
    """
    PySec Live Importer Pipeline

    Collect advisories from OSV PyPI zip for a single PURL.
    """

    pipeline_id = "pysec_live_importer_v2"
    supported_types = ["pypi"]

    @classmethod
    def steps(cls):
        return (
            cls.get_purl_inputs,
            cls.fetch_zip,
            cls.collect_and_store_advisories,
        )

    def get_purl_inputs(self):
        purl = self.inputs["purl"]
        if not purl:
            raise ValueError("PURL is required for PySecLiveImporterPipeline")

        if isinstance(purl, str):
            purl = PackageURL.from_string(purl)

        if not isinstance(purl, PackageURL):
            raise ValueError(f"Object of type {type(purl)} {purl!r} is not a PackageURL instance")

        if purl.type not in self.supported_types:
            raise ValueError(
                f"PURL: {purl!s} is not among the supported package types {self.supported_types!r}"
            )

        if not purl.version:
            raise ValueError(f"PURL: {purl!s} is expected to have a version")

        self.purl = purl

    def _is_version_affected(self, advisory_dict, version):
        affected = advisory_dict.get("affected", [])
        try:
            v = PypiVersion(version)
        except Exception:
            return False
        for entry in affected:
            ranges = entry.get("ranges", [])
            for r in ranges:
                events = r.get("events", [])
                introduced = None
                fixed = None
                for event in events:
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                try:
                    if introduced:
                        introduced_v = PypiVersion(introduced)
                        if v < introduced_v:
                            continue
                    if fixed:
                        fixed_v = PypiVersion(fixed)
                        if v >= fixed_v:
                            continue
                    if introduced:
                        introduced_v = PypiVersion(introduced)
                        if (not fixed or v < PypiVersion(fixed)) and v >= introduced_v:
                            return True
                except Exception:
                    continue
        return False

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        from vulnerabilities.importers.osv import parse_advisory_data_v2

        with ZipFile(BytesIO(self.advisory_zip)) as zip_file:
            for file_name in zip_file.namelist():
                if not file_name.startswith("PYSEC-"):
                    continue
                with zip_file.open(file_name) as f:
                    import json

                    advisory_dict = json.load(f)

                    affected = advisory_dict.get("affected", [])
                    found = False
                    for entry in affected:
                        pkg = entry.get("package", {})
                        if pkg.get("name") == self.purl.name:
                            found = True
                            break
                    if not found:
                        continue
                    if not self._is_version_affected(advisory_dict, self.purl.version):
                        continue

                    f.seek(0)
                    advisory_text = f.read().decode("utf-8")
                    yield parse_advisory_data_v2(
                        raw_data=advisory_dict,
                        supported_ecosystems=["pypi"],
                        advisory_url=self.url,
                        advisory_text=advisory_text,
                    )
