#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from packageurl import PackageURL

from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import PackageVersionImprover
from vulnerabilities.models import Advisory


class ApacheHTTPDImprover(DefaultImprover, PackageVersionImprover):
    @property
    def interesting_advisories(self):
        return Advisory.objects.filter(created_by="apache_httpd_importer")

    def get_package_versions(self, package_url: PackageURL):
        if package_url.type != "apache" or package_url.name != "httpd":
            return []
        return self.fetch_apache_httpd_versions()

    def fetch_apache_httpd_versions(self):
        """
        Fetch all Apache HTTPD versions from the official website.
        """
        import requests
        from bs4 import BeautifulSoup

        url = "https://httpd.apache.org/download.cgi"
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        versions = []

        # Find all version links in the download page
        for link in soup.find_all("a"):
            href = link.get("href", "")
            if "httpd-" in href and ".tar.gz" in href:
                version = href.split("httpd-")[1].split(".tar.gz")[0]
                versions.append(version)

        return sorted(versions, reverse=True) 