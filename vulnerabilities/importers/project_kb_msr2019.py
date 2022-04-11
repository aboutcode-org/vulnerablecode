# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import csv
import urllib.request

from vulnerabilities.helpers import create_etag
from vulnerabilities.helpers import is_cve
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference

# Reading CSV file from  a url using `requests` is bit too complicated.
# Use `urllib.request` for that purpose.


class ProjectKBMSRImporter(Importer):

    url = "https://raw.githubusercontent.com/SAP/project-kb/master/MSR2019/dataset/vulas_db_msr2019_release.csv"

    def updated_advisories(self):
        if create_etag(data_src=self, url=self.url, etag_key="ETag"):
            raw_data = self.fetch()
            advisories = self.to_advisories(raw_data)
            return self.batch_advisories(advisories)

        return []

    def fetch(self):
        response = urllib.request.urlopen(self.url)
        lines = [l.decode("utf-8") for l in response.readlines()]
        return csv.reader(lines)

    @staticmethod
    def to_advisories(csv_reader):
        # Project KB MSR csv file has no header row
        advisories = []
        for row in csv_reader:
            vuln_id, proj_home, fix_commit, _ = row
            commit_link = proj_home + "/commit/" + fix_commit

            if is_cve(vuln_id):
                reference = Reference(url=commit_link)

            else:
                reference = Reference(url=commit_link, reference_id=vuln_id)
                vuln_id = ""

            advisories.append(
                AdvisoryData(
                    summary="",
                    affected_packages=[],
                    references=[reference],
                    vulnerability_id=vuln_id,
                )
            )

        return advisories
