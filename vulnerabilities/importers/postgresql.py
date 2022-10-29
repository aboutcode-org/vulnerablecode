#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import urllib.parse as urlparse

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL

# is there a univers versionrange?  a version?
from univers.version_range import GenericVersionRange
from univers.versions import GenericVersion

from vulnerabilities import severity_systems

# add AffectedPackage
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity

# we no longer use nearest_patched_package, do we?
from vulnerabilities.utils import nearest_patched_package


class PostgreSQLImporter(Importer):

    root_url = "https://www.postgresql.org/support/security/"
    # need spdx_license_expression and license_url

    def updated_advisories(self):
        advisories = []
        known_urls = {self.root_url}
        visited_urls = set()
        while True:
            unvisited_urls = known_urls - visited_urls
            for url in unvisited_urls:
                data = requests.get(url).content
                advisories.extend(to_advisories(data))
                visited_urls.add(url)
                known_urls.update(find_advisory_urls(data))

            if known_urls == visited_urls:
                break

        return self.batch_advisories(advisories)


def to_advisories(data):
    print("\n\n>> This is a test.")
    print("\n=====")
    advisories = []
    soup = BeautifulSoup(data, features="lxml")
    table = soup.select("table")[0]
    test_row_count = 0
    for row in table.select("tbody tr"):
        test_row_count += 1
        print("\ntest_row_count = {}".format(test_row_count))
        ref_col, affected_col, fixed_col, severity_score_col, desc_col = row.select("td")
        summary = desc_col.text
        pkg_qualifiers = {}
        if "windows" in summary.lower():
            pkg_qualifiers = {"os": "windows"}

        # affected_packages = [
        #     PackageURL(
        #         type="generic",
        #         name="postgresql",
        #         version=version.strip(),
        #         qualifiers=pkg_qualifiers,
        #     )
        #     for version in affected_col.text.split(",")
        # ]

        # fixed_packages = [
        #     PackageURL(
        #         type="generic",
        #         name="postgresql",
        #         version=version.strip(),
        #         qualifiers=pkg_qualifiers,
        #     )
        #     for version in fixed_col.text.split(",")
        #     # why the "if version" here but not in affected_packages?
        #     # aren't we assuming (can we assume?) there are an equal number of versions in affect_packages and fixed_packages?
        #     if version
        # ]

        # This will replace the affected_packages and fixed_packages lists above. ============
        affected_packages = []
        # do I need to trim these?  e.g., affected_version_list = [x.strip() for x in affected_col.text.split(',')]
        affected_version_list = affected_col.text.split(",")
        fixed_version_list = fixed_col.text.split(",")
        package_count = len(affected_version_list)

        print("\naffected_version_list = {}".format(affected_version_list))
        print("\nfixed_version_list = {}".format(fixed_version_list))
        print("\npackage_count = {}".format(package_count))

        while package_count > 0:
            summary = summary

            affected = affected_version_list[0]
            affected_version_list.pop(0)
            # Do we need "if affected else None"?
            affected_version_range = (
                GenericVersionRange.from_versions([affected]) if affected else None
            )

            fixed = fixed_version_list[0]
            fixed_version_list.pop(0)
            # Do we need "if fixed else None"?
            fixed_version = GenericVersion(fixed) if fixed else None

            package_count -= 1

            affected_package = AffectedPackage(
                package=PackageURL(
                    name="postgresql",
                    type="generic",
                    namespace="postgresql",
                    qualifiers=pkg_qualifiers,
                ),
                affected_version_range=affected_version_range,
                fixed_version=fixed_version,
            )
            affected_packages.append(affected_package)

            print("\naffected_package = {}".format(affected_package))
            print("\n\taffected_package.package = {}".format(affected_package.package))
            print(
                "\n\taffected_package.affected_version_range = {}".format(
                    affected_package.affected_version_range
                )
            )
            print("\n\taffected_package.fixed_version = {}".format(affected_package.fixed_version))

            print("\ninterim package_count = {}".format(package_count))

            # end of initial draft insert ===================================

        try:
            cve_id = ref_col.select("nobr")[0].text
            # This is for the anomaly in https://www.postgresql.org/support/security/8.1/ 's
            # last entry
            # Note: in this example and others, final entry/entries have no CVE in the 1st column
        except IndexError:
            pass

        references = []
        vector_link_tag = severity_score_col.find("a")
        for a_tag in ref_col.select("a"):
            link = a_tag.attrs["href"]
            if link.startswith("/"):
                # Convert relative urls to absolute url.
                # All links qualify this criteria, so this `if` statement is kind of a defensive mechanism
                link = urlparse.urljoin("https://www.postgresql.org/", link)
                severities = []
                if "support/security/CVE" in link and vector_link_tag:
                    parsed_link = urlparse.urlparse(vector_link_tag["href"])
                    cvss3_vector = urlparse.parse_qs(parsed_link.query)["vector"]
                    cvss3_base_score = vector_link_tag.text
                    severity = VulnerabilitySeverity(
                        system=severity_systems.CVSSV3,
                        value=cvss3_base_score,
                        scoring_elements=cvss3_vector,
                    )
                    severities.append(severity)
            references.append(Reference(url=link, severities=severities))

        advisories.append(
            AdvisoryData(
                # 10/26/2022 Wednesday 6:40:01 PM.  Throws error (terminal points to test data): TypeError: __init__() got an unexpected keyword argument 'vulnerability_id'
                # vulnerability_id=cve_id,
                aliases=[cve_id],
                summary=summary,
                references=references,
                # affected_packages=nearest_patched_package(affected_packages, fixed_packages),
                affected_packages=affected_packages,
            )
        )

        print("\n------------------------------------")

    print("\ntotal test_advisories (i.e., AdvisoryData objects) = {}".format(len(advisories)))
    print("\nadvisories = {}".format(advisories))

    test_advisory_count = 0
    for test_advisory in advisories:
        test_advisory_count += 1
        print("\ntest_advisory #{} = {}".format(test_advisory_count, test_advisory))
        print("\n\ttest_advisory.aliases = {}".format(test_advisory.aliases))
        print("\n\ttest_advisory.summary = {}".format(test_advisory.summary))
        print("\n\ttest_advisory.affected_packages = {}".format(test_advisory.affected_packages))
        for test_affected_package in test_advisory.affected_packages:
            print("\n\ttest_affected_package = {}".format(test_affected_package))
            print("\n\t\ttest_affected_package.package = {}".format(test_affected_package.package))
            print(
                "\n\t\ttest_affected_package.affected_version_range = {}".format(
                    test_affected_package.affected_version_range
                )
            )
            print(
                "\n\t\ttest_affected_package.fixed_version = {}".format(
                    test_affected_package.fixed_version
                )
            )
        print("\n\ttest_advisory.references = {}".format(test_advisory.references))
        for test_reference in test_advisory.references:
            print("\n\ttest_test_reference = {}".format(test_reference))

    print("\n------------------------------------")

    print("\n>> This is the end of the test.\n")

    return advisories


def find_advisory_urls(page_data):
    soup = BeautifulSoup(page_data)
    return {
        urlparse.urljoin("https://www.postgresql.org/", a_tag.attrs["href"])
        for a_tag in soup.select("h3+ p a")
    }
