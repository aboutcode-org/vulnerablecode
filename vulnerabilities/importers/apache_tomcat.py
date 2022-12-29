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
import urllib

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import APACHE_TOMCAT

TRACE = False


class ApacheTomcatImporter(Importer):

    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/"

    temp_list_of_fixed_versions = []
    temp_advisory_dict_list = []
    updated_temp_advisory_dict_list = []
    record_of_all_affects_elements = []
    record_of_all_affects_strings = []
    record_of_all_affected_version_strings = []

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
        Return a list of AdvisoryData.
        """
        advisories = []

        for advisory_page in self.fetch_advisory_pages(self.security_updates_home):
            advisories.extend(self.extract_advisories_from_page(advisory_page))

        if TRACE:
            self.debug_advisory_data(advisories)

        return advisories

    def debug_advisory_data(self, advisories):

        apache_tomcat_advisories = "apache_tomcat_advisories_refactored-02.txt"

        with open(apache_tomcat_advisories, "w") as f:
            for advisory in advisories:
                f.write(f"{advisory}\n")

        temp_advisory_to_dict_list = []
        for adv in advisories:
            adv_dict = adv.to_dict()
            temp_advisory_to_dict_list.append(adv_dict)

        with open(
            "apache_tomcat_advisories_to_dict-02.json",
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(temp_advisory_to_dict_list, f, ensure_ascii=False, indent=4)

        with open(
            "apache_tomcat_fixed_version_list-00.txt",
            "w",
        ) as f:
            for line in self.temp_list_of_fixed_versions:
                f.write(f"{line}\n")

        with open(
            "apache_tomcat_advisory_dict_list-00.json",
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(self.temp_advisory_dict_list, f, ensure_ascii=False, indent=4)

        with open(
            "apache_tomcat_advisory_dict_list-00-updated.json",
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(self.updated_temp_advisory_dict_list, f, ensure_ascii=False, indent=4)

        tomcat_affects_elements = "record_of_all_affects_elements-2022-12-27-00.txt"
        with open(tomcat_affects_elements, "w") as f:
            for line in self.record_of_all_affects_elements:
                f.write(f"{line}\n")

        tomcat_affects_strings = "record_of_all_affects_strings-2022-12-27-00.txt"
        with open(tomcat_affects_strings, "w") as f:
            for line in self.record_of_all_affects_strings:
                f.write(f"{line}\n")

        tomcat_affected_version_strings = "record_of_all_affected_version_strings-2022-12-27-00.txt"
        with open(tomcat_affected_version_strings, "w") as f:
            for line in self.record_of_all_affected_version_strings:
                f.write(f"{line}\n")

    # 2022-12-29 Thursday 13:11:16.  We're in the process of refactoring this method.
    # See, e.g., function with the same name at the bottom of this file.
    def extract_advisories_from_page(self, apache_tomcat_advisory_html):
        """
        Return a list of AdvisoryData extracted from the HTML text ``apache_tomcat_advisory_html``.
        """
        page_soup = BeautifulSoup(apache_tomcat_advisory_html, features="lxml")
        # We're looking for headers -- one for each advisory -- like this:
        # <h3 id="Fixed_in_Apache_Tomcat_10.0.27"><span class="pull-right">2022-10-10</span> Fixed in Apache Tomcat 10.0.27</h3>
        pageh3s = page_soup.find_all("h3")
        fixed_version_headings = [
            heading for heading in pageh3s if "Fixed in Apache Tomcat" in heading.text
        ]

        advisories = []
        for fixed_version_heading in fixed_version_headings:
            fixed_versions = []
            fixed_version = fixed_version_heading.text.split("Fixed in Apache Tomcat")[-1].strip()
            if TRACE:
                print("fixed_version = {}".format(fixed_version))

            # We want to handle the occasional "and" in the fixed version headers, e.g.,
            # <h3 id="Fixed_in_Apache_Tomcat_8.5.5_and_8.0.37"><span class="pull-right">5 September 2016</span> Fixed in Apache Tomcat 8.5.5 and 8.0.37</h3>
            if " and " in fixed_version:
                fixed_versions = fixed_version.split(" and ")
            else:
                fixed_versions.append(fixed_version)

            if TRACE:
                print("fixed_versions = {}".format(fixed_versions))

            # Each group of fixed-version-related data is contained in a div that immediately follows the h3 element, e.g.,
            # <h3 id="Fixed_in_Apache_Tomcat_8.5.8"><span class="pull-right">8 November 2016</span> Fixed in Apache Tomcat 8.5.8</h3>
            # <div class="text"> ... <div>
            fixed_version_paras = fixed_version_heading.find_next_sibling()

            # See https://tomcat.apache.org/security-impact.html for scoring.
            # Each advisory section starts with a <p> element,
            # the text of which starts with, e.g., "Low:", so we look for these here, e.g.,
            # <p><strong>Low: Apache Tomcat request smuggling</strong><a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-42252" rel="nofollow">CVE-2022-42252</a></p>
            severities = ("Low:", "Moderate:", "Important:", "High:", "Critical:")
            # A list of groups of paragraphs, each for a single Tomcat Advisory.
            advisory_groups = []
            current_group = []
            for para in fixed_version_paras.find_all("p"):
                if para.text.startswith(severities):
                    if current_group:
                        current_group = []
                    else:
                        advisory_groups.append(current_group)

                    current_group.append(para)

                else:
                    if current_group:
                        current_group.append(para)
                    else:
                        pass

                    severity_score = para.text.split(" ")[0]
                    severity_score = severity_score.split(":")[0]
                    print("\nseverity_score = {}\n".format(severity_score))

                    print("===")

                    better_cve_url_list = para.find_all("a")
                    print("better_cve_url_list = {}\n".format(better_cve_url_list))

                    better_cve_id_list = [cve_text.text for cve_text in better_cve_url_list]
                    print("better_cve_id_list = {}\n".format(better_cve_id_list))

                    for better_cve_url in para.find_all("a"):
                        print("better_cve_url = {}\n".format(better_cve_url))
                        print("better_cve_url.text = {}".format(better_cve_url.text))

                    better_nextSiblings = para.find_next_siblings()

                    print("===")

                    section_parent = para.find_parent()

                    cve_url_list = section_parent.find_all("a")
                    print("cve_url_list = {}\n".format(cve_url_list))

                    cve_id_list = [cve_text.text for cve_text in cve_url_list]
                    print("cve_id_list = {}\n".format(cve_id_list))

                    for cve_url in section_parent.find_all("a"):
                        print("cve_url = {}\n".format(cve_url))
                        print("cve_url.text = {}".format(cve_url.text))

                    nextSiblings = section_parent.find_next_siblings()

                    print("===")

                    fixed_commit_list = []
                    affected_versions = []

                    for sib in better_nextSiblings:
                        if "was fixed in" in sib.text or "was fixed with" in sib.text:
                            print("\nnext sib (was fixed) = {}".format(sib))
                            fixed_commit_list = sib.find_all("a")
                            print("\nfixed_commit_list = {}".format(fixed_commit_list))

                        elif "Affects" in sib.text:
                            print("\nnext sib (affects) = {}\n".format(sib))

                            # 2022-12-27 Tuesday 18:47:28.  We need the list of `sib` elements to examine -- and test -- the raw HTML.
                            self.record_of_all_affects_elements.append(sib)

                            # 2022-12-27 Tuesday 14:47:51.  We'll examine the affects_string and try to find and remove unwanted alpha and related characters/strings.
                            # ===
                            # This version is before stripping/replacing etc.
                            affects_string = sib.text.split("Affects:")[-1].strip()
                            print("affects_string = {}\n".format(affects_string))
                            self.record_of_all_affects_strings.append(affects_string)

                            affected_versions = affects_string.split(", ")
                            print("> affected_versions = {}\n".format(affected_versions))
                            self.record_of_all_affected_version_strings.append(affected_versions)
                            # ===
                            # This version is with most but not all of the stripping/replacing.
                            # affects_string = sib.text.split("Affects:")[-1].strip()
                            # affects_string = affects_string.replace("\n", "")
                            # affects_string = " ".join(affects_string.split())
                            # affects_string_no_parens = re.sub(r" ?\([^)]+\)", "", affects_string)
                            # # print("affects_string = {}\n".format(affects_string))
                            # # self.record_of_all_affects_strings.append(affects_string)
                            # print(
                            #     "affects_string_no_parens = {}\n".format(affects_string_no_parens)
                            # )
                            # self.record_of_all_affects_strings.append(affects_string_no_parens)

                            # # affected_versions = affects_string.split(", ")
                            # affected_versions = affects_string_no_parens.split(", ")
                            # print("> affected_versions = {}\n".format(affected_versions))
                            # self.record_of_all_affected_version_strings.append(affected_versions)
                            # ===

                        elif sib.find_all(
                            "strong",
                            text=lambda text: text and text.startswith(tuple(severities)),
                        ):
                            break

                    # Starting to flesh out this new approach.
                    # for cve_id_record in cve_id_list:
                    #     test_advisory_dict["fixed_versions"] = fixed_versions
                    #     test_advisory_dict["aliases"] = [cve_id_record]

                    temp_dict_list = []

                    print("\n1.  affected_versions = {}\n".format(affected_versions))

                    for better_cve_id_record in better_cve_id_list:
                        # 2022-12-26 Monday 14:41:11.  This is where `test_advisory_dict = {}` belongs!  Now we have data for the double-CVEs!
                        test_advisory_dict = {}
                        test_advisory_dict["fixed_versions"] = fixed_versions
                        test_advisory_dict["aliases"] = [better_cve_id_record]

                        self.updated_temp_advisory_dict_list.append(test_advisory_dict)

                        print(
                            "==========================> better_cve_id_record = {}".format(
                                better_cve_id_record
                            )
                        )

                        temp_dict_list.append(test_advisory_dict)

                        # TODO: 2022-12-26 Monday 14:55:49.  Is this where we build the "better" AdvisoryData() objects?
                        better_severities = []
                        better_severities.append(
                            VulnerabilitySeverity(
                                system=APACHE_TOMCAT,
                                value=severity_score,
                                scoring_elements="",
                            )
                        )

                        print("\n2.  affected_versions = {}\n".format(affected_versions))

                        affected_version_range = self.to_version_ranges(
                            # versions_data, fixed_versions
                            affected_versions,
                            # TODO: 2022-12-26 Monday 16:01:08.  fix this!
                            # ["1.1"],
                            # ["8.5.0 to 8.5.4", " 8.0.0.RC1 to 8.0.36"],
                            # ["3.0", " 3.1-3.1.1", " 3.2-3.2.1"],
                            # TODO: 2022-12-26 Monday 17:56:04.  This identified the problem -- a space at the start of the 2nd range!
                            # ["8.5.0 to 8.5.4", "8.0.0.RC1 to 8.0.36"],
                            fixed_versions,
                        )
                        references = [
                            Reference(
                                # url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                                url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={better_cve_id_record}",
                                # reference_id=cve_id,
                                reference_id=better_cve_id_record,
                                # severities=severities,
                                severities=better_severities,
                            ),
                        ]

                        # for commit_url in fixed_in_commits:
                        for commit_url in fixed_commit_list:
                            # references.append(Reference(url=commit_url))
                            # TODO: 2022-12-26 Monday 17:23:38.  Does this fix the error TypeError: Object of type Tag is not JSON serializable?  Yes.
                            references.append(Reference(url=commit_url["href"]))

                        # 2022-12-26 Monday 15:37:02.  Does this belong here?
                        affected_packages = []

                        affected_packages.append(
                            AffectedPackage(
                                package=PackageURL(
                                    type="maven",
                                    namespace="apache",
                                    name="tomcat",
                                ),
                                affected_version_range=affected_version_range,
                            )
                        )

                        advisories.append(
                            AdvisoryData(
                                aliases=[better_cve_id_record],
                                summary="",
                                affected_packages=affected_packages,
                                references=references,
                            )
                        )

                    self.temp_list_of_fixed_versions.append(fixed_versions)

        return advisories

    def to_version_ranges(self, versions_data, fixed_versions):
        constraints = []

        for version_item in versions_data:
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


@dataclasses.dataclass(order=True)
class TomcatAdvisoryData:
    fixed_versions: list
    advisory_groups: list

    def to_dict(self):
        advisory_groups_to_strings = []
        # Convert bs4 para to string.
        for group in self.advisory_groups:
            advisory_groups_to_strings.append([str(para) for para in group])
        return {
            "fixed_versions": self.fixed_versions,
            "advisory_groups": advisory_groups_to_strings,
        }


def extract_advisories_from_page(apache_tomcat_advisory_html):
    """
    Yield TomcatAdvisoryData from the HTML text ``apache_tomcat_advisory_html``.
    """
    page_soup = BeautifulSoup(apache_tomcat_advisory_html, features="lxml")
    # We're looking for headers -- one for each advisory -- like this:
    # <h3 id="Fixed_in_Apache_Tomcat_10.0.27"><span class="pull-right">2022-10-10</span> Fixed in Apache Tomcat 10.0.27</h3>
    pageh3s = page_soup.find_all("h3")
    fixed_version_headings = [
        heading for heading in pageh3s if "Fixed in Apache Tomcat" in heading.text
    ]

    for fixed_version_heading in fixed_version_headings:
        fixed_versions = []
        fixed_version = fixed_version_heading.text.split("Fixed in Apache Tomcat")[-1].strip()
        if TRACE:
            print("fixed_version = {}".format(fixed_version))
            print("===========================")

        # We want to handle the occasional "and" in the fixed version headers, e.g.,
        # <h3 id="Fixed_in_Apache_Tomcat_8.5.5_and_8.0.37"><span class="pull-right">5 September 2016</span> Fixed in Apache Tomcat 8.5.5 and 8.0.37</h3>
        if " and " in fixed_version:
            fixed_versions = fixed_version.split(" and ")
        else:
            fixed_versions.append(fixed_version)

        if TRACE:
            print("fixed_versions = {}".format(fixed_versions))
            print("===========================")

        # Each group of fixed-version-related data is contained in a div that immediately follows the h3 element, e.g.,
        # <h3 id="Fixed_in_Apache_Tomcat_8.5.8"><span class="pull-right">8 November 2016</span> Fixed in Apache Tomcat 8.5.8</h3>
        # <div class="text"> ... <div>
        fixed_version_paras = fixed_version_heading.find_next_sibling()

        # See https://tomcat.apache.org/security-impact.html for scoring.
        # Each advisory section starts with a <p> element,
        # the text of which starts with, e.g., "Low:", so we look for these here, e.g.,
        # <p><strong>Low: Apache Tomcat request smuggling</strong><a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-42252" rel="nofollow">CVE-2022-42252</a></p>
        severities = ("Low:", "Moderate:", "Important:", "High:", "Critical:")
        # A list of groups of paragraphs, each for a single Tomcat Advisory.
        advisory_groups = []

        for para in fixed_version_paras.find_all("p"):
            current_group = []
            if para.text.startswith(severities):
                current_group.append(para)

                test_nextSiblings = para.find_next_siblings()
                for next_sibling in test_nextSiblings:
                    if not next_sibling.text.startswith(severities):
                        current_group.append(next_sibling)
                    elif next_sibling.text.startswith(severities):
                        break

                advisory_groups.append(current_group)

        if TRACE:
            print("\ncurrent_group = {}\n".format(current_group))
            print("\nadvisory_groups = {}\n".format(advisory_groups))

        yield TomcatAdvisoryData(fixed_versions=fixed_versions, advisory_groups=advisory_groups)
