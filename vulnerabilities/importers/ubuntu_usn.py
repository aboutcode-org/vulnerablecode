#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import bz2
import json

import requests

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.utils import is_cve


class UbuntuUSNImporter(Importer):
    db_url = "https://usn.ubuntu.com/usn-db/database-all.json.bz2"
    spdx_license_expression = "GPL"

    def advisory_data(self):
        usn_db = fetch(self.db_url)
        yield from self.to_advisories(usn_db=usn_db)

    @staticmethod
    def to_advisories(usn_db):
        for usn in usn_db:
            usn_data = usn_db[usn]
            references = get_usn_references(usn_data.get("id"))
            for cve in usn_data.get("cves", []):
                # The db sometimes contains entries like
                # {'cves': ['python-pgsql vulnerabilities', 'CVE-2006-2313', 'CVE-2006-2314']}
                # This `if` filters entries like 'python-pgsql vulnerabilities'
                if not is_cve(cve):
                    continue

                yield AdvisoryData(
                    aliases=[cve],
                    summary="",
                    references=references,
                )


def get_usn_references(usn_id):
    if not usn_id:
        return []
    return [Reference(reference_id=f"USN-{usn_id}", url=f"https://usn.ubuntu.com/{usn_id}/")]


def fetch(url):
    response = requests.get(url).content
    raw_data = bz2.decompress(response)

    return json.loads(raw_data)
