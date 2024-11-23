#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

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

    # See https://github.com/nexB/vulnerablecode/issues/36 for follow up
    spdx_license_expression = (
        "LicenseRef-scancode-us-govt-public-domain  AND LicenseRef-scancode-cve-tou"
    )
    license_url = "https://nvd.nist.gov/general/FAQ-Sections/General-FAQs#faqLink7"
    """
    EXAMPLE:
        {
            "cve_id": "CVE-2020-11979",
            "pkg": "apache-ant",
            "cve_score": 7.5,
            "aff_ver": "all versions before 1.10.8-2.ph1 are vulnerable",
            "res_ver": "1.10.8-2.ph1"
        },
        {
            "cve_id": "CVE-2020-1945",
            "pkg": "apache-ant",
            "cve_score": 6.3,
            "aff_ver": "all versions before 1.10.8-1.ph1 are vulnerable",
            "res_ver": "1.10.8-1.ph1"
        },
        {
            "cve_id": "CVE-2021-36373",
            "pkg": "apache-ant",
            "cve_score": 5.5,
            "aff_ver": "all versions before 1.10.8-4.ph1 are vulnerable",
            "res_ver": "1.10.8-4.ph1"
        }
    """
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
        if VMWAREPHOTONImporterPipeline.advisories_count():
            VMWAREPHOTONImporterPipeline.to_advisory(self.data)


    def to_advisory(data):
        advisories=[]
        for cve in data:
            cve_id=cve.get("cve_id")
            pkg=cve.get("pkg")
            cve_scoore=cve.get("cve_score")
            aff_ver=cve.get("aff_ver")
            rev_ver=cve.get("res_ver")

        """
        Returns an AdvisoryData object from this CVE item and adds it to the advisory list
        """
        advisories.append(
             AdvisoryData(
                 
                aliases=cve_id,
                affected_packages=pkg,
                
            )
        )
        return advisories

