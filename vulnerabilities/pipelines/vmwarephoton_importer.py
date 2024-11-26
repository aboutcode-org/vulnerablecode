import gzip
import json
import logging
from datetime import date
from traceback import format_exc as traceback_format_exc
from typing import Iterable

import attr
import requests
from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_range import VersionRange
from univers.versions import GenericVersion  # Import GenericVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item


class VMWAREPHOTONImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect advisories from VMWARE_PHOTON."""

    '''
    EXAMPLE:
    {
    "cve_id": "CVE-2020-11979",
    "pkg": "apache-ant",
    "cve_score": 7.5,
    "aff_ver": "all versions before 1.10.8-2.ph1 are vulnerable",
    "res_ver": "1.10.8-2.ph1"
    }
    '''

    pipeline_id = "vmwarephoton_importer"
    repo_url = "https://github.com/vmware/photon/wiki/Security-Advisories"
    spdx_license_expression = "CC BY-SA 4.0"
    license_url = "https://creativecommons.org/licenses/by-sa/4.0/"

    importer_name = "PHOTON Importer"

    urls = [
        "https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon1.0.json",
        "https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon2.0.json",
        "https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon3.0.json",
        "https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon4.0.json",
        "https://packages.vmware.com/photon/photon_cve_metadata/cve_data_photon5.0.json",
    ]

    def advisories_count(self):
        advisory_count = 0
        for url in self.urls:
            try:
                response = requests.get(url)
                response.raise_for_status()
                data = response.json()
                advisory_count += len(data)
            except requests.HTTPError as http_err:
                self.log(
                    f"HTTP error occurred while fetching {url}: {http_err} \n {traceback_format_exc()}",
                    level=logging.ERROR,
                )
            except requests.RequestException as req_err:
                self.log(
                    f"Request exception occurred while fetching {url}: {req_err} \n {traceback_format_exc()}",
                    level=logging.ERROR,
                )
            except Exception as e:
                self.log(f"Unexpected error: {e} \n {traceback_format_exc()}", level=logging.ERROR)
        return advisory_count

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        advisories = []
        for url in self.urls:
            try:
                response = requests.get(url)
                response.raise_for_status()
                advisories_data = response.json()  # Fetch the data from the API
                advisories.extend(self.to_advisory(advisories_data))  # Collect advisories for each URL
            except requests.HTTPError as http_err:
                self.log(
                    f"HTTP error occurred while fetching {url}: {http_err} \n {traceback_format_exc()}",
                    level=logging.ERROR,
                )
            except requests.RequestException as req_err:
                self.log(
                    f"Request exception occurred while fetching {url}: {req_err} \n {traceback_format_exc()}",
                    level=logging.ERROR,
                )
            except Exception as e:
                self.log(f"Unexpected error: {e} \n {traceback_format_exc()}", level=logging.ERROR)
        return advisories

    def to_advisory(self, data) -> Iterable[AdvisoryData]:
        advisories = []
        for cve in data:
            cve_id = cve.get("cve_id")
            pkg_name = cve.get("pkg")
            aff_ver = cve.get("aff_ver")
            rev_ver = cve.get("res_ver")
            url = cve.get("url", "https://github.com/vmware/photon/wiki/Security-Advisories")  # Default URL

            # Validate required fields and skip invalid entries
            if not cve_id or not pkg_name or not aff_ver or not rev_ver:
                logging.warning(f"Skipping advisory due to missing fields: {cve}")
                continue

            try:
                # Create a PackageURL object
                pkg = PackageURL(name=pkg_name, type="generic")

                # Use GenericVersion to handle non-semver versions
                try:
                    fixed_version = GenericVersion(rev_ver)
                except ValueError as e:
                    logging.warning(f"Skipping advisory {cve_id} due to invalid version: {rev_ver} - {e}")
                    continue

                affected_version_range = None
                if "all versions before" in aff_ver.lower():
                    affected_version_range = f"vers:generic/<{rev_ver}"

                # Handle version range errors
                try:
                    affected_packages = [
                        AffectedPackage(
                            package=pkg,
                            affected_version_range=VersionRange.from_string(affected_version_range)
                            if affected_version_range
                            else None,
                            fixed_version=fixed_version,
                        )
                    ]
                except ValueError as ve:
                    logging.warning(f"Skipping advisory {cve_id} due to invalid version range: {aff_ver} - {ve}")
                    continue

                advisories.append(
                    AdvisoryData(
                        aliases=[cve_id],
                        affected_packages=affected_packages,
                        url=url,  # Ensure a valid URL is provided
                    )
                )
            except Exception as e:
                logging.error(f"Error processing advisory {cve_id}: {e}")
                continue

        return advisories
