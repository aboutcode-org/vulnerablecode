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
    spdx_license_expression = "LicenseRef-scancode-other-permissive"
    notice = """
    From: Seth Arnold <seth.arnold@canonical.com>
    Date: Wed, Jan 25, 2023 at 2:02 AM
    Subject: Re: [ubuntu-hardened] Usage of Ubuntu Security Data in VulnerableCode
    To: Tushar Goel <tushar.goel.dav@gmail.com>
    Cc: <ubuntu-hardened@lists.ubuntu.com>, Philippe Ombredanne <pombredanne@nexb.com>, jmhoran@nexb.com <jmhoran@nexb.com>
    
    
    On Wed, Jan 11, 2023 at 06:27:38PM +0530, Tushar Goel wrote:
    > We would like to integrate the Ubuntu usn data[1][2] and
    > Ubuntu security data (OVAL format)[3] in vulnerablecode[4]
    > which is a FOSS db of FOSS vulnerability data. We were not
    > able to know under which license this security data comes.
    > We would be grateful to have your acknowledgement over usage of
    > the ubuntu security data in vulnerablecode and have
    > some kind of licensing declaration from your side.
    
    Hello Tushar, we do not have an explicit license on this data.
    
    We share our data with the intention that others will use it. Please
    feel free to use it for the general furtherance of security.
    
    Much of the data that's contained within our databases is sourced from
    third parties, who also shared their data with the intention that others
    will use it. I'm not sure what it would look like to try to put a license
    on data that is crowd-sourced from thousands of contributors. (If you were
    to start such a project today, it'd probably be one of the first things to
    formalize. But when CVE was started two decades ago, the primary goal was
    sharing knowledge and simplifying the vulnerability remediation process,
    and licensing the data was, as far as I can remember, not considered.
    Sharing was the goal.)
    
    I will ask that vulnerablecode 'be nice' to our infrastructure that
    hosts the databases -- some automated uses of our infrastructure by
    vulnerability scanner tools has lead to significant load and engineering
    effort. In general, please prefer a small handful of systems updating
    mirrors roughly twice a day rather than thousands of hosts pulling
    data hourly.
    
    Thanks
    """

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
