#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.utils import is_cve

# Reading CSV file from  a url using `requests` is bit too complicated.
# Use `urllib.request` for that purpose.


class ProjectKBMSRImporter(Importer):
    url = "https://raw.githubusercontent.com/SAP/project-kb/master/MSR2019/dataset/vulas_db_msr2019_release.csv"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/SAP/project-kb/blob/main/LICENSE.txt"

    def advisory_data(self):
        raw_data = fetch_and_read_from_csv(self.url)
        yield from self.to_advisories(raw_data)

    def to_advisories(self, csv_reader):
        # Project KB MSR csv file has no header row
        for row in csv_reader:
            vuln_id, proj_home, fix_commit, _ = row
            commit_link = proj_home + "/commit/" + fix_commit

            if not is_cve(vuln_id):
                continue

            reference = Reference(url=commit_link)
            yield AdvisoryData(
                aliases=[vuln_id],
                summary="",
                references=[reference],
            )
