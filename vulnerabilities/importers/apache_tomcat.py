#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses
import json
import logging
import urllib
from collections import namedtuple

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import ApacheVersionRange
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import APACHE_TOMCAT

LOGGER = logging.getLogger(__name__)

# For temporary data testing.
PRINT = False
TRACE = True
record_of_all_affects_elements = []
record_of_all_affected_versions = []
record_of_all_reported_cves = []
record_of_all_reported_advisories = []
record_of_all_reported_advisories_test01 = []
record_of_all_reported_advisories_test02 = []
record_of_all_reported_advisories_test03 = []


corrective_data_mapping = {
    ("not released Fixed in Apache Tomcat 9.0.9", "CVE-2018-8014"): {
        "fixed_versions": ["9.0.9"],
        "affected_versions": ["9.0.0.M1 to 9.0.8"],
    },
    ("6 July 2018 Fixed in Apache Tomcat 8.0.53", "CVE-2018-8014"): {
        "fixed_versions": ["8.0.53"],
        "affected_versions": ["8.0.0.RC1 to 8.0.52"],
    },
    ("26 June 2018 Fixed in Apache Tomcat 8.5.32", "CVE-2018-8014"): {
        "fixed_versions": ["8.5.32"],
        "affected_versions": ["8.5.0 to 8.5.31"],
    },
    ("not released Fixed in Apache Tomcat 7.0.89", "CVE-2018-8014"): {
        "fixed_versions": ["7.0.89"],
        "affected_versions": ["7.0.41 to 7.0.88"],
    },
    ("16 May 2018 Fixed in Apache Tomcat 7.0.88", "CVE-2018-1336"): {
        "fixed_versions": ["7.0.88"],
        "affected_versions": ["7.0.28 to 7.0.86"],
    },
    ("released 21 Jan 2010 Fixed in Apache Tomcat 6.0.24", "CVE-2009-2901"): {
        "fixed_versions": ["6.0.24"],
        "affected_versions": ["6.0.0-6.0.20"],
    },
    ("released 20 Apr 2010 Fixed in Apache Tomcat 5.5.29", "CVE-2009-2901"): {
        "fixed_versions": ["5.5.29"],
        "affected_versions": ["5.5.0-5.5.28"],
    },
    ("released 4 Sep 2009 Fixed in Apache Tomcat 5.5.28", "CVE-2009-0580"): {
        "fixed_versions": ["5.5.28"],
        "affected_versions": ["5.5.0-5.5.27"],
    },
    ("not released Fixed in Apache Tomcat 5.5.21", "CVE-2008-4308"): {
        "fixed_versions": ["5.5.21"],
        "affected_versions": ["5.5.10-5.5.20"],
    },
    ("Fixed in Apache Tomcat 5.5.1", "CVE-2008-3271"): {
        "fixed_versions": ["5.5.1"],
        "affected_versions": ["5.5.0"],
    },
    ("Will not be fixed in Apache Tomcat 4.1.x", "CVE-2005-4836"): {
        "fixed_versions": [],
        "affected_versions": ["4.1.15-4.1.SVN"],
    },
    ("Fixed in Apache Tomcat 4.1.40", "CVE-2009-0580"): {
        "fixed_versions": ["4.1.40"],
        "affected_versions": ["4.1.0-4.1.39"],
    },
    ("Fixed in Apache Tomcat 4.1.35", "CVE-2008-4308"): {
        "fixed_versions": ["4.1.35"],
        "affected_versions": ["4.1.32-4.1.34"],
    },
    ("Fixed in Apache Tomcat 4.1.3", "CVE-2002-0935"): {
        "fixed_versions": ["4.1.3"],
        "affected_versions": ["4.0.0-4.0.2", "4.0.3", "4.0.4-4.0.6", "4.1.0-4.1.2"],
    },
    ("Fixed in Apache Tomcat 4.0.0", "CVE-2002-0493"): {
        "fixed_versions": ["4.0.0"],
        "affected_versions": ["<4.0.0"],
    },
    ("Not fixed in Apache Tomcat 3.x", "CVE-2005-0808"): {
        "fixed_versions": [],
        "affected_versions": ["3.0", "3.1-3.1.1", "3.2-3.2.4", "3.3a-3.3.2"],
    },
    ("Not fixed in Apache Tomcat 3.x", "CVE-2007-3382"): {
        "fixed_versions": [],
        "affected_versions": ["3.3-3.3.2"],
    },
    ("Not fixed in Apache Tomcat 3.x", "CVE-2007-3384"): {
        "fixed_versions": [],
        "affected_versions": ["3.3-3.3.2"],
    },
    ("Not fixed in Apache Tomcat 3.x", "CVE-2007-3385"): {
        "fixed_versions": [],
        "affected_versions": ["3.3-3.3.2"],
    },
    ("Fixed in Apache Tomcat 3.2.4", "CVE-2001-1563"): {
        "fixed_versions": ["3.2.4"],
        "affected_versions": ["3.2", "3.2.1", "3.2.2-3.2.3"],
    },
}


class ApacheTomcatImporter(Importer):

    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/LICENSE-2.0"

    def fetch_advisory_pages(self):
        """
        Yield the content of each HTML page containing version-related security data.
        """
        links = self.fetch_advisory_links("https://tomcat.apache.org/security")
        for page_url in links:
            yield requests.get(page_url).content

    def fetch_advisory_links(self, url):
        """
        Yield the URLs of each Tomcat version security-related page.
        Each page link is in the form of `https://tomcat.apache.org/security-10.html`,
        for instance, for v10.
        """
        data = requests.get(url).content
        soup = BeautifulSoup(data, features="lxml")
        for tag in soup.find_all("a"):
            link = tag.get("href")

            if "security-" in link and any(char.isdigit() for char in link):
                yield urllib.parse.urljoin(url, link)

    def advisory_data(self):
        """
        Return a list of AdvisoryData objects.
        """
        advisories = []

        for advisory_page in self.fetch_advisory_pages():
            advisories.extend(self.extract_advisories_from_page(advisory_page))

        # This is what we want -- 243 advisory_data_objects = 243 "fixed version" groups.
        for adv in advisories:
            record_of_all_reported_advisories.append(adv)

        if TRACE:
            self.debug_advisory_data(advisories)

        if PRINT:
            print("\nlen(advisories) = {}\n".format(len(advisories)))

            advisories_list = list(advisories)
            for adv in advisories_list:
                print("adv = {}".format(adv))

        return advisories

    def debug_advisory_data(self, advisories):

        tomcat_affects_elements = "vulnerabilities/tests/test_data/apache_tomcat/trace/record_of_all_affects_elements-2023-01-04-00.txt"
        with open(tomcat_affects_elements, "w") as f:
            for line in record_of_all_affects_elements:
                f.write(f"{line}\n")

        tomcat_affected_versions = "vulnerabilities/tests/test_data/apache_tomcat/trace/record_of_all_affected_versions-2023-01-04-00.txt"
        with open(tomcat_affected_versions, "w") as f:
            for line in record_of_all_affected_versions:
                f.write(f"{line}\n")

        tomcat_reported_cves = "vulnerabilities/tests/test_data/apache_tomcat/trace/record_of_all_reported_cves-2023-01-04-00.txt"
        with open(tomcat_reported_cves, "w") as f:
            for line in record_of_all_reported_cves:
                f.write(f"{line}\n")

        tomcat_reported_advisories = "vulnerabilities/tests/test_data/apache_tomcat/trace/record_of_all_reported_advisories-2023-01-06-00.txt"
        with open(tomcat_reported_advisories, "w") as f:
            for line in record_of_all_reported_advisories:
                f.write(f"{line}\n")

        tomcat_reported_advisories_test01 = "vulnerabilities/tests/test_data/apache_tomcat/trace/record_of_all_reported_advisories_test01-2023-01-06-00.txt"
        with open(tomcat_reported_advisories_test01, "w") as f:
            for line in record_of_all_reported_advisories_test01:
                f.write(f"{line}\n")

        tomcat_reported_advisories_test02 = "vulnerabilities/tests/test_data/apache_tomcat/trace/record_of_all_reported_advisories_test02-2023-01-06-00.txt"
        with open(tomcat_reported_advisories_test02, "w") as f:
            for line in record_of_all_reported_advisories_test02:
                f.write(f"{line}\n")

        tomcat_reported_advisories_test03 = "vulnerabilities/tests/test_data/apache_tomcat/trace/record_of_all_reported_advisories_test03-2023-01-06-00.txt"
        with open(tomcat_reported_advisories_test03, "w") as f:
            for line in record_of_all_reported_advisories_test03:
                f.write(f"{line}\n")

    def extract_advisories_from_page(self, apache_tomcat_advisory_html):
        """
        Return a list of AdvisoryData objects extracted from the HTML text ``apache_tomcat_advisory_html``.
        """
        advisories = []

        # This yields groups of advisories organized by Tomcat fixed versions -- 1+ per group.
        fixed_version_advisory_groups = extract_tomcat_advisory_data_from_page(
            apache_tomcat_advisory_html
        )

        for advisory_group in fixed_version_advisory_groups:
            advisory_data_objects = generate_advisory_data_objects(advisory_group)

            if PRINT:
                print("\n>>> advisory_data_objects = {}".format(advisory_data_objects))

            if TRACE:
                for advisory_data_object in advisory_data_objects:
                    record_of_all_reported_advisories_test03.append(advisory_data_object)

                    if PRINT:
                        print("\nadvisory_data_object = {}\n".format(advisory_data_object))
                        print(
                            "\nadvisory_data_object.to_dict() = {}\n".format(
                                advisory_data_object.to_dict()
                            )
                        )

                    adv_dict = advisory_data_object.to_dict()
                    if PRINT:
                        print(json.dumps(adv_dict, indent=4, sort_keys=False))

                    record_of_all_reported_advisories_test01.append(adv_dict)

            advisories.append(advisory_data_objects)

        return advisories


@dataclasses.dataclass(order=True)
class TomcatAdvisoryData:
    fixed_versions: list
    advisory_groups: list
    # 2023-01-09 Monday 14:43:24.  Use this as 1st key in dict?
    fixed_version_heading_text: str

    def to_dict(self):
        advisory_groups_to_strings = []
        # Convert bs4 para to string.
        for group in self.advisory_groups:
            advisory_groups_to_strings.append([str(para) for para in group])
        return {
            "fixed_versions": self.fixed_versions,
            "advisory_groups": advisory_groups_to_strings,
        }


def extract_tomcat_advisory_data_from_page(apache_tomcat_advisory_html):
    """
    Yield TomcatAdvisoryData from the HTML text ``apache_tomcat_advisory_html``.
    """
    page_soup = BeautifulSoup(apache_tomcat_advisory_html, features="lxml")
    # We're looking for headers -- one for each advisory -- like this:
    # <h3 id="Fixed_in_Apache_Tomcat_10.0.27"><span class="pull-right">2022-10-10</span> Fixed in Apache Tomcat 10.0.27</h3>
    pageh3s = page_soup.find_all("h3")

    # fixed_version_headings = [
    #     heading for heading in pageh3s if "Fixed in Apache Tomcat" in heading.text
    # ]

    # Include the 2 groups of not-fixed advisories.
    fixed_header_substrings = (
        "Fixed in Apache Tomcat",
        "Will not be fixed in Apache Tomcat 4.1.x",
        "Not fixed in Apache Tomcat 3.x",
    )
    fixed_version_headings = [
        heading
        for heading in pageh3s
        if any(
            fixed_header_substring in heading.text
            for fixed_header_substring in fixed_header_substrings
        )
    ]

    for fixed_version_heading in fixed_version_headings:
        if PRINT:
            print("\n==================================================\n")
            print("*** fixed_version_heading.text = {} ***".format(fixed_version_heading.text))

        fixed_versions = []
        # fixed_version = fixed_version_heading.text.split("Fixed in Apache Tomcat")[-1].strip()
        fixed_version = ""

        # # 2023-01-09 Monday 10:31:29.  Include the 2 groups of not-fixed advisories.
        # # We report no value for those that won't be fixed.
        if "Fixed in Apache Tomcat" in fixed_version_heading.text:
            fixed_version = fixed_version_heading.text.split("Fixed in Apache Tomcat")[-1].strip()
        elif "Will not be fixed in Apache Tomcat 4.1.x" in fixed_version_heading.text:
            fixed_version = fixed_version_heading.text.split("Will not be fixed in Apache Tomcat")[
                -1
            ].strip()
        elif "Not fixed in Apache Tomcat 3.x" in fixed_version_heading.text:
            fixed_version = fixed_version_heading.text.split("Not fixed in Apache Tomcat")[
                -1
            ].strip()

        # We want to handle the occasional "and" in the fixed version headers, e.g.,
        # <h3 id="Fixed_in_Apache_Tomcat_8.5.5_and_8.0.37"><span class="pull-right">5 September 2016</span> Fixed in Apache Tomcat 8.5.5 and 8.0.37</h3>
        if " and " in fixed_version:
            fixed_versions = fixed_version.split(" and ")
        else:
            fixed_versions.append(fixed_version)

        if PRINT:
            print("*** fixed_versions = {} ***\n".format(fixed_versions))

        # Each group of fixed-version-related data is contained in a div that immediately follows the h3 element, e.g.,
        # <h3 id="Fixed_in_Apache_Tomcat_8.5.8"><span class="pull-right">8 November 2016</span> Fixed in Apache Tomcat 8.5.8</h3>
        # <div class="text"> ... <div>
        fixed_version_paras = fixed_version_heading.find_next_sibling()

        # See https://tomcat.apache.org/security-impact.html for scoring.
        # Each advisory section starts with a <p> element,
        # the text of which starts with, e.g., "Low:", so we look for these here, e.g.,
        # <p><strong>Low: Apache Tomcat request smuggling</strong><a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-42252" rel="nofollow">CVE-2022-42252</a></p>

        severity_scores = ("Low:", "Moderate:", "Important:", "High:", "Critical:")
        # A list of groups of paragraphs, each for a single Tomcat Advisory.
        advisory_groups = []

        for para in fixed_version_paras.find_all("p"):
            current_group = []
            if para.text.startswith(severity_scores):
                current_group.append(para)

                test_next_siblings = para.find_next_siblings()
                for next_sibling in test_next_siblings:
                    if not next_sibling.text.startswith(severity_scores):
                        current_group.append(next_sibling)
                    elif next_sibling.text.startswith(severity_scores):
                        break

                advisory_groups.append(current_group)

        # yield TomcatAdvisoryData(fixed_versions=fixed_versions, advisory_groups=advisory_groups)
        # fixed_version_heading.text
        yield TomcatAdvisoryData(
            fixed_versions=fixed_versions,
            advisory_groups=advisory_groups,
            fixed_version_heading_text=fixed_version_heading.text,
        )


def generate_advisory_data_objects(tomcat_advisory_data_object):

    fixed_versions = tomcat_advisory_data_object.fixed_versions

    severity_scores = ("Low:", "Moderate:", "Important:", "High:", "Critical:")

    for para_list in tomcat_advisory_data_object.advisory_groups:
        affected_versions = []
        fixed_commit_list = []
        references = []
        cve_url_list = []
        for para in para_list:

            if para.text.startswith("Affects:"):
                if TRACE:
                    record_of_all_affects_elements.append(para.text)

                if PRINT:
                    print("\npara.text startswith affects = {}".format(para.text))

                formatted_affected_version_data = para.text.split(":")[-1].split(", ")
                if PRINT:
                    print(
                        "\nformatted_affected_version_data = {}\n".format(
                            formatted_affected_version_data
                        )
                    )

                affected_versions.extend(formatted_affected_version_data)

                if PRINT:
                    print("\naffected_versions = {}".format(affected_versions))

            elif "was fixed in" in para.text or "was fixed with" in para.text:
                fixed_commit_list = para.find_all("a")
                if PRINT:
                    print("\nfixed_commit_list = {}\n".format(fixed_commit_list))

                references.extend([ref_url["href"] for ref_url in fixed_commit_list])
            elif para.text.startswith(severity_scores):
                cve_url_list = para.find_all("a")
                cve_list = [cve_url.text for cve_url in cve_url_list]
                if PRINT:
                    print("\n==> cve_list = {}".format(cve_list))

                severity_score = para.text.split(":")[0]

        for cve_url in cve_url_list:
            if PRINT:
                print("\n^^^ cve_url = {}\n".format(cve_url))
            aliases = []
            aliases.append(cve_url.text)

            severity_list = []
            severity_list.append(
                VulnerabilitySeverity(
                    system=APACHE_TOMCAT,
                    value=severity_score,
                    scoring_elements="",
                )
            )

            # # Check the dictionary and supply/replace needed values.  Convert `fixed_versions`` list
            # # to a tuple so it's hashable and thus can serve as part of a tuple-based dictionary key.
            # if PRINT:
            #     print("fixed_versions before update if any = {}".format(fixed_versions))
            #     print("affected_versions before update if any = {}\n".format(affected_versions))

            # fixed_versions_tuple = tuple(fixed_versions)

            # if (fixed_versions_tuple, cve_url.text) in corrective_data_mapping.keys():
            #     if PRINT:
            #         print("\n\n-- REPLACE/CORRECT VERSION DATA --  \n\n")
            #     fixed_versions = corrective_data_mapping[fixed_versions_tuple, cve_url.text][
            #         "fixed_versions"
            #     ]
            #     affected_versions = corrective_data_mapping[fixed_versions_tuple, cve_url.text][
            #         "affected_versions"
            #     ]
            # else:
            #     pass

            # 2023-01-09 Monday 14:48:34.  Use the fixed header string in place of the tuple
            # Check the dictionary and supply/replace needed values.
            if PRINT:
                print("fixed_versions before update if any = {}".format(fixed_versions))
                print("affected_versions before update if any = {}\n".format(affected_versions))

            # fixed_versions_tuple = tuple(fixed_versions)
            # 2023-01-09 Monday 14:45:55.  Try this as the 1st dict key:
            fixed_version_heading_text = tomcat_advisory_data_object.fixed_version_heading_text

            if (fixed_version_heading_text, cve_url.text) in corrective_data_mapping.keys():
                if PRINT:
                    print("\n\n-- REPLACE/CORRECT VERSION DATA --  \n\n")
                fixed_versions = corrective_data_mapping[fixed_version_heading_text, cve_url.text][
                    "fixed_versions"
                ]
                affected_versions = corrective_data_mapping[
                    fixed_version_heading_text, cve_url.text
                ]["affected_versions"]
            else:
                pass

            if PRINT:
                print("==> reported_cve = {}\n".format(cve_url.text))
                print("fixed_versions after update if any = {}".format(fixed_versions))
                print("affected_versions after update if any = {}".format(affected_versions))
            if TRACE:
                record_of_all_reported_cves.append(cve_url.text)
                record_of_all_affected_versions.append(affected_versions)

            # try:
            #     affected_version_range_apache = to_version_ranges_apache(
            #         affected_versions,
            #         fixed_versions,
            #     )
            # except Exception as e:
            #     LOGGER.error(f"{affected_versions!r} is not a valid SemverVersion {e!r}")
            #     continue

            affected_version_range_apache = to_version_ranges_apache(
                affected_versions,
                fixed_versions,
            )

            affected_version_range_maven = to_version_ranges_maven(
                affected_versions,
                fixed_versions,
            )

            references = [
                Reference(
                    url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_url.text}",
                    reference_id=cve_url.text,
                    severities=severity_list,
                ),
            ]

            for commit_url in fixed_commit_list:
                references.append(Reference(url=commit_url["href"]))

            affected_packages = []

            affected_packages.append(
                AffectedPackage(
                    package=PackageURL(
                        type="apache",
                        name="tomcat",
                    ),
                    affected_version_range=affected_version_range_apache,
                )
            )

            affected_packages.append(
                AffectedPackage(
                    package=PackageURL(
                        type="maven",
                        namespace="org.apache.tomcat",
                        name="tomcat",
                    ),
                    affected_version_range=affected_version_range_maven,
                )
            )

            if TRACE:
                temp_advisory_data_object = AdvisoryData(
                    aliases=aliases,
                    summary="",
                    affected_packages=affected_packages,
                    references=references,
                )

                temp_advisory_dict = temp_advisory_data_object.to_dict()

                record_of_all_reported_advisories_test02.append(temp_advisory_dict)

            yield AdvisoryData(
                aliases=aliases,
                summary="",
                affected_packages=affected_packages,
                references=references,
            )


def to_version_ranges_apache(versions_data, fixed_versions):
    constraints = []

    VersionConstraintTuple = namedtuple("VersionConstraintTuple", ["comparator", "version"])
    affected_constraint_tuple_list = []
    fixed_constraint_tuple_list = []

    for version_item in versions_data:
        version_item = version_item.strip()
        if "to" in version_item:
            version_item_split = version_item.split(" ")

            # constraints.append(
            #     VersionConstraint(
            #         comparator=">=",
            #         version=SemverVersion(version_item_split[0]),
            #     )
            # )
            # constraints.append(
            #     VersionConstraint(
            #         comparator="<=",
            #         version=SemverVersion(version_item_split[-1]),
            #     )
            # )

            affected_constraint_tuple_list.append(
                VersionConstraintTuple(">=", version_item_split[0])
            )
            affected_constraint_tuple_list.append(
                VersionConstraintTuple("<=", version_item_split[-1])
            )

        elif "-" in version_item:
            version_item_split = version_item.split("-")

            # constraints.append(
            #     VersionConstraint(
            #         comparator=">=",
            #         version=SemverVersion(version_item_split[0]),
            #     )
            # )
            # constraints.append(
            #     VersionConstraint(
            #         comparator="<=",
            #         version=SemverVersion(version_item_split[-1]),
            #     )
            # )

            affected_constraint_tuple_list.append(
                VersionConstraintTuple(">=", version_item_split[0])
            )
            affected_constraint_tuple_list.append(
                VersionConstraintTuple("<=", version_item_split[-1])
            )

        elif version_item.startswith("<"):
            version_item_split = version_item.split("<")

            # constraints.append(
            #     VersionConstraint(
            #         comparator="<",
            #         version=SemverVersion(version_item_split[-1]),
            #     )
            # )

            affected_constraint_tuple_list.append(
                VersionConstraintTuple("<", version_item_split[-1])
            )

        else:
            version_item_split = version_item.split(" ")

            # constraints.append(
            #     VersionConstraint(
            #         comparator="=",
            #         version=SemverVersion(version_item_split[0]),
            #     )
            # )

            affected_constraint_tuple_list.append(
                VersionConstraintTuple("=", version_item_split[0])
            )

    for fixed_item in fixed_versions:

        if "-" in fixed_item and not any([i.isalpha() for i in fixed_item]):
            fixed_item_split = fixed_item.split(" ")

            # constraints.append(
            #     VersionConstraint(
            #         comparator=">=",
            #         version=SemverVersion(fixed_item_split[0]),
            #     ).invert()
            # )
            # constraints.append(
            #     VersionConstraint(
            #         comparator="<=",
            #         version=SemverVersion(fixed_item_split[-1]),
            #     ).invert()
            # )

            fixed_constraint_tuple_list.append(VersionConstraintTuple(">=", fixed_item_split[0]))
            fixed_constraint_tuple_list.append(VersionConstraintTuple("<=", fixed_item_split[-1]))

        else:
            fixed_item_split = fixed_item.split(" ")

            # constraints.append(
            #     VersionConstraint(
            #         comparator="=",
            #         version=SemverVersion(fixed_item_split[0]),
            #     ).invert()
            # )

            fixed_constraint_tuple_list.append(VersionConstraintTuple("=", fixed_item_split[0]))

    for record in affected_constraint_tuple_list:
        try:
            constraints.append(
                VersionConstraint(
                    comparator=record.comparator,
                    version=SemverVersion(record.version),
                )
            )
        except Exception as e:
            LOGGER.error(f"{record.version!r} is not a valid SemverVersion {e!r}")
            continue

    for record in fixed_constraint_tuple_list:
        constraints.append(
            VersionConstraint(
                comparator=record.comparator,
                version=SemverVersion(record.version),
            ).invert()
        )

    return ApacheVersionRange(constraints=constraints)


def to_version_ranges_maven(versions_data, fixed_versions):
    constraints = []

    for version_item in versions_data:
        version_item = version_item.strip()
        if "to" in version_item:
            version_item_split = version_item.split(" ")

            constraints.append(
                VersionConstraint(
                    comparator=">=",
                    version=MavenVersion(version_item_split[0]),
                )
            )
            constraints.append(
                VersionConstraint(
                    comparator="<=",
                    version=MavenVersion(version_item_split[-1]),
                )
            )

        elif "-" in version_item:
            version_item_split = version_item.split("-")

            constraints.append(
                VersionConstraint(
                    comparator=">=",
                    version=MavenVersion(version_item_split[0]),
                )
            )
            constraints.append(
                VersionConstraint(
                    comparator="<=",
                    version=MavenVersion(version_item_split[-1]),
                )
            )

        elif version_item.startswith("<"):
            version_item_split = version_item.split("<")

            constraints.append(
                VersionConstraint(
                    comparator="<",
                    version=MavenVersion(version_item_split[-1]),
                )
            )

        else:
            version_item_split = version_item.split(" ")

            constraints.append(
                VersionConstraint(
                    comparator="=",
                    version=MavenVersion(version_item_split[0]),
                )
            )

    for fixed_item in fixed_versions:

        if "-" in fixed_item and not any([i.isalpha() for i in fixed_item]):
            fixed_item_split = fixed_item.split(" ")

            constraints.append(
                VersionConstraint(
                    comparator=">=",
                    version=MavenVersion(fixed_item_split[0]),
                ).invert()
            )
            constraints.append(
                VersionConstraint(
                    comparator="<=",
                    version=MavenVersion(fixed_item_split[-1]),
                ).invert()
            )

        else:
            fixed_item_split = fixed_item.split(" ")

            constraints.append(
                VersionConstraint(
                    comparator="=",
                    version=MavenVersion(fixed_item_split[0]),
                ).invert()
            )

    return MavenVersionRange(constraints=constraints)
