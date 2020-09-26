# Copyright (c)  nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import dataclasses
import gzip
import json
from dateutil import parser as dateparser
from datetime import date

import requests

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.helpers import create_etag
from vulnerabilities.severity_systems import scoring_systems


@dataclasses.dataclass
class NVDDataSourceConfiguration(DataSourceConfiguration):
    etags: dict


BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz"


class NVDDataSource(DataSource):

    CONFIG_CLASS = NVDDataSourceConfiguration

    def updated_advisories(self):
        current_year = date.today().year
        # NVD json feeds start from 2002.
        for year in range(2002, current_year + 1):
            download_url = BASE_URL.format(year)
            # Etags are like hashes of web responses. We maintain
            # (url, etag) mappings in the DB. `create_etag`  creates
            # (url, etag) pair. If a (url, etag) already exists then the code
            # skips processing the response further to avoid duplicate work
            if create_etag(data_src=self, url=download_url, etag_key="etag"):
                data = self.fetch(download_url)
                yield self.to_advisories(data)

    @staticmethod
    def fetch(url):
        gz_file = requests.get(url)
        data = gzip.decompress(gz_file.content)
        return json.loads(data)

    def to_advisories(self, nvd_data):
        for cve_item in nvd_data["CVE_Items"]:
            if self.is_outdated(cve_item):
                continue

            if self.related_to_hardware(cve_item):
                continue

            cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
            ref_urls = self.extract_reference_urls(cve_item)
            references = [Reference(url=url) for url in ref_urls]
            severity_scores = self.extract_severity_scores(cve_item)
            references.append(
                Reference(
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    reference_id=cve_id,
                    severities=severity_scores,
                )
            )
            summary = self.extract_summary(cve_item)
            yield Advisory(
                identifier=cve_id, summary=summary, vuln_references=references, impacted_package_urls=[]  # nopep8
            )

    @staticmethod
    def extract_summary(cve_item):
        # In 99% of cases len(cve_item['cve']['description']['description_data']) == 1 , so
        # this usually returns  cve_item['cve']['description']['description_data'][0]['value']
        # In the remaining 1% cases this returns the longest summary.
        summaries = [desc["value"] for desc in cve_item["cve"]["description"]["description_data"]]
        return max(summaries, key=len)

    @staticmethod
    def extract_severity_scores(cve_item):
        severity_scores = []

        if cve_item["impact"].get("baseMetricV3"):
            severity_scores.append(
                VulnerabilitySeverity(
                    system=scoring_systems["cvssv3"],
                    value=str(cve_item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]),
                )
            )
            severity_scores.append(
                VulnerabilitySeverity(
                    system=scoring_systems["cvssv3_vector"],
                    value=str(cve_item["impact"]["baseMetricV3"]["cvssV3"]["vectorString"]),
                )
            )

        if cve_item["impact"].get("baseMetricV2"):
            severity_scores.append(
                VulnerabilitySeverity(
                    system=scoring_systems["cvssv2"],
                    value=str(cve_item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]),
                )
            )
            severity_scores.append(
                VulnerabilitySeverity(
                    system=scoring_systems["cvssv2_vector"],
                    value=str(cve_item["impact"]["baseMetricV2"]["cvssV2"]["vectorString"]),
                )
            )

        return severity_scores

    def extract_reference_urls(self, cve_item):
        urls = set()
        for reference in cve_item["cve"]["references"]["reference_data"]:
            ref_url = reference["url"]

            if not ref_url:
                continue

            if ref_url.startswith("http") or ref_url.startswith("ftp"):
                urls.add(ref_url)

        return urls

    def is_outdated(self, cve_item):
        cve_last_modified_date = cve_item["lastModifiedDate"]
        cve_last_modified_date_obj = dateparser.parse(cve_last_modified_date)

        if self.config.cutoff_date:
            return cve_last_modified_date_obj < self.config.cutoff_date

        if self.config.last_run_date:
            return cve_last_modified_date_obj < self.config.last_run_date

        return False

    def related_to_hardware(self, cve_item):
        for cpe in self.extract_cpes(cve_item):
            cpe_comps = cpe.split(":")
            # CPE follow the format cpe:cpe_version:product_type:vendor:product
            if cpe_comps[2] == "h":
                return True

        return False

    @staticmethod
    def extract_cpes(cve_item):
        cpes = set()
        for node in cve_item["configurations"]["nodes"]:
            for cpe_data in node.get("cpe_match", []):
                cpes.add(cpe_data["cpe23Uri"])
        return cpes
