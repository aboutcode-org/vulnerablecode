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
    spdx_license_expression = "GPL-2"
    license_url = "https://wiki.xenproject.org/wiki/Xen_FAQ_General"

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
       #TODO: https://github.com/nexB/vulnerablecode/issues/981
            if not is_cve(cve):
                continue
            yield AdvisoryData(
                aliases=[cve],
                summary=title,
                references=references,
            )
