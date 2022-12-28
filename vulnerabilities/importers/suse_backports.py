#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import requests
import saneyaml
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.versions import RpmVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.utils import fetch_yaml


class SUSEBackportsImporter(Importer):

    spdx_license_expression = "TBD"

    def get_all_urls_of_backports(self, url):
        r = requests.get(url)
        soup = BeautifulSoup(r.content, "lxml")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href") or ""
            if href.endswith(".yaml") and href.startswith("backports"):
                yield url + a_tag["href"]

    def advisory_data(self):
        url = "http://ftp.suse.com/pub/projects/security/yaml/"
        all_urls = self.get_all_urls_of_backports(url=url)
        for url in all_urls:
            yield from self.process_file(fetch_yaml(url))

    def process_file(self, yaml_file):
        if not yaml_file:
            return []
        data = yaml_file[0]
        for pkg in data.get("packages") or []:
            package_data = data["packages"][pkg]
            for version in package_data.get("fixed") or []:
                version_data = package_data["fixed"][version]
                for vuln in version_data:
                    # yaml_file specific data can be added
                    package = PackageURL(name=pkg, type="rpm", namespace="opensuse")
                    yield AdvisoryData(
                        aliases=[vuln],
                        summary="",
                        affected_packages=[
                            AffectedPackage(package=package, fixed_version=RpmVersion(version))
                        ],
                    )
