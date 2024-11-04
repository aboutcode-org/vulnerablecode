#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import urllib.parse as urlparse
from typing import Iterable
import logging
from traceback import format_exc as traceback_format_exc
import datetime

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.versions import GenericVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.utils import get_advisory_url


class OpenJDKImporterPipeline(VulnerableCodeBaseImporterPipeline):
    """Collect advisories from OpenJDK."""

    pipeline_id = "openjdk_importer"
    root_url = "https://openjdk.org/groups/vulnerability/advisories/"
    license_url = "https://openjdk.org/legal/"
    spdx_license_expression = "CC-BY-4.0"
    importer_name = "OpenJDK Importer"

    @classmethod
    def steps(cls):
        return (
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
        )

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        data_by_urls, publish_dates = self.advisory_data()
        for url, data in data_by_urls.items():
            yield from to_advisories(data, date_published=publish_dates[url])

    def advisories_count(self) -> int:
        advisory_count = 0
        try:
            response = requests.get(self.root_url)
            response.raise_for_status()

            advisory_data = response.text
            

        except requests.HTTPError as http_err:
            self.log(
                f"HTTP error occurred: {http_err} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )
            return advisory_count

        advisory_count = advisory_data.count("<li>")
        return advisory_count

    def advisory_data(self):

        extracted_urls = []
        data_by_urls = {}
        publish_dates = {}

        # scraping the advisory urls
        data = requests.get(self.root_url).text
        soup = BeautifulSoup(data, features="lxml")
        li_tags = soup.find_all("li")
        li_contents = [li.get_text(strip=True) for li in li_tags]

        for link in li_contents:
            link = link.split()[0]  # for getting only the year links

            #getting publish dates in datetime format
            date_string = link
            date_format = "%Y/%m/%d" 
            date_object = datetime.datetime.strptime(date_string, date_format)

            link = "-".join(link.split("/"))
            link = self.root_url + link
            extracted_urls.append(link)
            data_by_urls[link] = requests.get(link).text
            publish_dates[link] = date_object

        return data_by_urls, publish_dates
        # for url, data in data_by_urls.items():
        #     yield from to_advisories(data, date_published=link)


def to_advisories(data, date_published) -> Iterable[AdvisoryData]:
    advisories = []
    soup_spec = BeautifulSoup(data, features="lxml")
    table_tags = soup_spec.find_all("table")
    # print(soup_spec.find_all('th'))

    # tables containing the vulnurability info of OpenJDK and OpenJFX

    # For OpenJDK vulnerability data
    try:
        OpenJDK_table = table_tags[0]
        extract_table_advisories(advisories, OpenJDK_table, date_published)
    except IndexError:
        pass

    # For OpenJFX vulnerability data
    try:
        OpenJFX_table = table_tags[1]
        extract_table_advisories(advisories, OpenJFX_table, date_published)
    except IndexError:
        pass

    return advisories


def extract_table_advisories(advisories, OpenJDK_table, date_published):
    OpenJDK_tr_tags = OpenJDK_table.select("tr")
    # print(OpenJDK_tr_tags)
    th_tags = OpenJDK_tr_tags[1].find_all("th")

    # to get the possible affected versions
    possible_affected_versions = []
    for i in range(3, len(th_tags)):
        possible_affected_versions.append(th_tags[i].text)

    scoring_system = OpenJDK_tr_tags[1].find("a").text
    link = OpenJDK_tr_tags[1].find("a").attrs["href"]
    for i in range(2, len(OpenJDK_tr_tags)):
        td_tags = OpenJDK_tr_tags[i].select("td")
        affected_version_list = []

        try:
            cve_id, component, severity_score, *affected_ver = td_tags
            # print(severity_score.text)
            if cve_id.text.startswith('CVE') is False:
                continue

            cve_url = cve_id.find("a").attrs["href"]
            cve_id = cve_id.text
            component = "".join(component.text.split("\n"))
            [cvss_score, cvss_vector] = severity_score.text.split("\n")

            references = []
            severities = []
            for index, version in enumerate(possible_affected_versions):
                if affected_ver[index].text:
                    affected_version_list.append(version)
                    severities.append(
                        VulnerabilitySeverity(
                            system=CVSSV3,
                            value=cvss_score,
                            scoring_elements=cvss_vector,
                        )
                    )

            references.append(Reference(url=link, severities=severities))

            affected_packages = []
            if affected_version_list:
                affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(
                            name="openjdk",
                            type="generic",
                        ),
                        affected_version_range=GenericVersionRange.from_versions(
                            affected_version_list
                        )
                        if affected_version_list
                        else None,
                    )
                )

            advisories.append(
                AdvisoryData(
                    aliases=[cve_id],
                    summary=component,
                    references=references,
                    affected_packages=affected_packages,
                    # date_published=date_published,
                    url=cve_url,
                )
            )

        # if vulnerability table is empty
        except LookupError:
            pass