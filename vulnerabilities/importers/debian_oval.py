# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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


import asyncio
import xml.etree.ElementTree as ET

import requests

from vulnerabilities.helpers import create_etag
from vulnerabilities.importer import OvalImporter
from vulnerabilities.package_managers import DebianVersionAPI


class DebianOvalImporter(OvalImporter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we could avoid setting translations, and have it
        # set by default in the OvalParser, but we don't yet know
        # whether all OVAL providers use the same format
        self.translations = {"less than": "<"}
        self.pkg_manager_api = DebianVersionAPI()

    def _fetch(self):
        releases = self.config.releases
        for release in releases:
            file_url = f"https://www.debian.org/security/oval/oval-definitions-{release}.xml"
            if not create_etag(data_src=self, url=file_url, etag_key="ETag"):
                continue

            resp = requests.get(file_url).content
            yield (
                {"type": "deb", "namespace": "debian", "qualifiers": {"distro": release}},
                ET.ElementTree(ET.fromstring(resp.decode("utf-8"))),
            )
        return []

    def set_api(self, packages):
        asyncio.run(self.pkg_manager_api.load_api(packages))
