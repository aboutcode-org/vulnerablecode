import dataclasses

from bs4 import BeautifulSoup
from packageurl import PackageURL
import requests
from urllib.parse import urljoin

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import Reference

SECURITY_UPDATES_URL = "https://mattermost.com/security-updates"


class MattermostDataSource(DataSource):

    def updated_advisories(self):
        #TODO: Add etags
        data = requests.get(SECURITY_UPDATES_URL).content
        return self.batch_advisories(self.to_advisories(data))

    def to_advisories(self, data):
        advisories = []
        #FIXME: Change after this https://forum.mattermost.org/t/mattermost-website-returning-403-when-headers-contain-the-word-python/11412
        soup = BeautifulSoup(data, features="lxml", headers={'user-agent': 'aboutcode/vulnerablecode'})
        for row in soup.table.tbody.find_all('tr'):
            ref_col, severity_score_col, affected_col,_, fixed_col, desc_col , name_col = row.select("td")
            summary = desc_col.text

            affected_packages = [
                PackageURL(
                    type="mattermost",
                    name=name_col,
                    version=version.strip(),
                    qualifiers=pkg_qualifiers,
                )
                for version in affected_col.text.split(",") #TODO: Not so easy
            ]

            fixed_packages = [
                PackageURL(
                    type="generic",
                    name="postgresql",
                    version=version.strip(),
                    qualifiers=pkg_qualifiers,
                )
                for version in fixed_col.text.split(",")
            ]
