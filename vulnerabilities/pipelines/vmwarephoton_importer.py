import gzip
import json
import logging
from datetime import date
from traceback import format_exc as traceback_format_exc
from typing import Iterable

import attr
import requests
from dateutil import parser as dateparser

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item


class VMWAREPHOTONImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect advisories from VMWARE_PHOTON."""

    pipeline_id = "vmwarephoton_importer"
    repo_url = "https://github.com/vmware/photon/wiki/Security-Advisories"
    spdx_license_expression = "CC BY-SA 4.0"
    license_url = "https://creativecommons.org/licenses/by-sa/4.0/"

    importer_name = "PHOTON Importer"

    def advisories_count(self):
        url = "https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon1.0.json"

        advisory_count = 0
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
        except requests.HTTPError as http_err:
            self.log(
                f"HTTP error occurred: {http_err} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )
            return advisory_count

        advisory_count = len(data)
        return advisory_count

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        # Fetch advisory data from the URL
        url = "https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon1.0.json"
        try:
            response = requests.get(url)
            response.raise_for_status()
            advisories_data = response.json()  # Fetch the data from the API
        except requests.HTTPError as http_err:
            self.log(
                f"HTTP error occurred: {http_err} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )
            return []

        # Pass the fetched data to the to_advisory method
        advisories = self.to_advisory(advisories_data)
        return advisories

    def to_advisory(self, data) -> Iterable[AdvisoryData]:
        advisories = []
        for cve in data:
            cve_id = cve.get("cve_id")
            pkg = cve.get("pkg")
            cve_score = cve.get("cve_score")
            aff_ver = cve.get("aff_ver")
            rev_ver = cve.get("res_ver")

            advisories.append(
                AdvisoryData(
                    aliases=[cve_id],  # Pass cve_id as aliases
                    affected_packages=[pkg],  # Package list
                    # cve_score = [cve_score],
                    # aff_ver = [aff_ver],
                    # rev_ver = [rev_ver]
                )
            )
        return advisories
