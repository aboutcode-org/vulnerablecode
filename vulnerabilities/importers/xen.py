# Copyright (c) nexB Inc. and others. All rights reserved.
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

import json

import requests

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.utils import create_etag
from vulnerabilities.utils import is_cve


class XenImporter(Importer):
    # CONFIG_CLASS = XenDBConfiguration

    def updated_advisories(self):
        advisories = []
        if create_etag(data_src=self, url=self.config.db_url, etag_key="etag"):
            advisories.extend(self.to_advisories(fetch(self.config.db_url)))

        return self.batch_advisories(advisories)

    def create_etag(self, url):
        etag = requests.head(url).headers.get("etag")
        if not etag:
            return True

        elif url in self.config.etags:
            if self.config.etags[url] == etag:
                return False

        self.config.etags[url] = etag
        return True

    @staticmethod
    def to_advisories(xen_db):
        advisories = []
        for xsa in xen_db[0]["xsas"]:
            reference = get_xen_references(xsa["xsa"])
            title = xsa.get("title", [""])
            for cve in xsa.get("cve", [""]):
                if not is_cve(cve):
                    cve = ""

                advisories.append(
                    AdvisoryData(
                        vulnerability_id=cve,
                        summary=title,
                        references=[reference],
                    )
                )
        return advisories


def get_xen_references(xsa_id):
    return Reference(
        reference_id="XSA-" + xsa_id,
        url="https://xenbits.xen.org/xsa/advisory-{}.html".format(xsa_id),
    )


def fetch(url):
    response = requests.get(url).content
    return json.loads(response)
