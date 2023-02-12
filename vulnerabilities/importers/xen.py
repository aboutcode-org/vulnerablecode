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
from vulnerabilities.references import XsaReference
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import is_cve


class XenImporter(Importer):
    url = "https://xenbits.xen.org/xsa/xsa.json"
    spdx_license_expression = "LicenseRef-scancode-other-permissive"
    notice = """
    From: George Dunlap <george.dunlap@cloud.com>
    Date: Wed, Jan 25, 2023 at 4:57 PM
    Subject: Re: Usage of Xen Security Data in VulnerableCode
    To: Tushar Goel <tushar.goel.dav@gmail.com>
    Cc: Andrew Cooper <Andrew.Cooper3@citrix.com>, xen-devel@lists.xenproject.org <xen-devel@lists.xenproject.org>, Xen Security <security@xen.org>, Philippe Ombredanne <pombredanne@nexb.com>, <jmhoran@nexb.com>

    On Thu, Jan 19, 2023 at 1:10 PM Tushar Goel <tushar.goel.dav@gmail.com> wrote:
    >
    > Hi Andrew,
    >
    > > Maybe we want to make it CC-BY-4 to require people to reference back to
    > > the canonical upstream ?
    > Thanks for your response, can we have a more declarative statement on
    > the license from your end
    > and also can you please provide your acknowledgement over the usage of
    > Xen security data in vulnerablecode.


    Hey Tushar,
    Informally, the Xen Project Security Team is happy for you to include the data from xsa.json in your open-source vulnerability database. As a courtesy we'd request that it be documented where the information came from. (I think if the data includes links to then advisories on our website, that will suffice.)
    Formally, we're not copyright lawyers; but we don't think there's anything copyright-able in the xsa.json: There is no editorial or creative control in the generation of that file; it's just a collection of facts which you could re-generate by scanning all the advisories. (In fact that's exactly how the file is created; i.e., the collection of advisory texts is our "source of truth".)
    We do have "Officially license all advisory text as CC-BY-4" on our to-do list; if you'd be more comfortable with an official license for xsa.json as well, we can add that to the list.

     -George
    """

    def advisory_data(self):
        data = fetch_response(self.url).json()
        # The data looks like this
        # [
        #  {
        #   "xsas": [
        #     {
        #       "cve": [
        #         "CVE-2012-5510"
        #       ],
        #       "title": "XSA-1: Xen security advisory",
        #       }
        #     ]
        #   }
        # ]
        if not data:
            return []
        xsas = data[0]["xsas"]
        for xsa in xsas:
            yield from self.to_advisories(xsa)

    def to_advisories(self, xsa):
        xsa_id = xsa.get("xsa")
        references = []
        if xsa_id:
            references.append(XsaReference.from_number(number=xsa_id))
        title = xsa.get("title")
        for cve in xsa.get("cve") or []:
            # TODO: https://github.com/nexB/vulnerablecode/issues/981
            if not is_cve(cve):
                continue
            yield AdvisoryData(
                aliases=[cve],
                summary=title,
                references=references,
            )
