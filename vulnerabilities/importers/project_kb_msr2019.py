#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import csv
import urllib.request

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.utils import create_etag
from vulnerabilities.utils import is_cve

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
