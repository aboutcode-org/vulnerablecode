#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# import json only for temporary testing
import json
import re

# import asyncio
import urllib

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.package_managers import MavenVersionAPI
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.utils import create_etag
from vulnerabilities.utils import nearest_patched_package


class ApacheTomcatImporter(Importer):

    base_url = "https://tomcat.apache.org/security-{}"
    security_updates_home = "https://tomcat.apache.org/security"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/"

    temp_list_of_fixed_versions = []

    temp_advisory_dict_list = []

    updated_temp_advisory_dict_list = []

    def updated_advisories(self):
        advisories = []

        for advisory_page in self.fetch_pages(self.security_updates_home):
            advisories.extend(self.to_advisories(advisory_page))

        apache_tomcat_advisories = "/mnt/c/wsl2-spyder-substitute-01/apache_tomcat_importer/apache_tomcat_advisories_refactored-02.txt"

        with open(apache_tomcat_advisories, "w") as f:
            for line in advisories:
                f.write(f"{line}\n")

        temp_advisory_to_dict_list = []
        for adv in advisories:
            adv_dict = adv.to_dict()
            temp_advisory_to_dict_list.append(adv_dict)

        with open(
            "/mnt/c/wsl2-spyder-substitute-01/apache_tomcat_importer/apache_tomcat_advisories_to_dict-02.json",
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(temp_advisory_to_dict_list, f, ensure_ascii=False, indent=4)

        with open(
            "/mnt/c/wsl2-spyder-substitute-01/apache_tomcat_importer/apache_tomcat_fixed_version_list-00.txt",
            "w",
        ) as f:
            for line in self.temp_list_of_fixed_versions:
                f.write(f"{line}\n")

        with open(
            "/mnt/c/wsl2-spyder-substitute-01/apache_tomcat_importer/apache_tomcat_advisory_dict_list-00.json",
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(self.temp_advisory_dict_list, f, ensure_ascii=False, indent=4)

        with open(
            "/mnt/c/wsl2-spyder-substitute-01/apache_tomcat_importer/apache_tomcat_advisory_dict_list-00-updated.json",
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(self.updated_temp_advisory_dict_list, f, ensure_ascii=False, indent=4)

        return advisories

    def fetch_links(self, url):
        links = []
        data = requests.get(url).content
        soup = BeautifulSoup(data, features="lxml")
        for tag in soup.find_all("a"):
            link = tag.get("href")

            if "security-" in link and any(char.isdigit() for char in link):
                links.append(urllib.parse.urljoin(url, link))

        return links

    def fetch_pages(self, security_updates_home):
        links = self.fetch_links(security_updates_home)
        for page_url in links:
            yield requests.get(page_url).content

    def to_advisories(self, apache_tomcat_advisory_html):
        advisories = []
        page_soup = BeautifulSoup(apache_tomcat_advisory_html, features="lxml")
        pageh3s = page_soup.find_all("h3")
        vuln_headings = [heading for heading in pageh3s if "Fixed in Apache Tomcat" in heading.text]

        for vuln_heading in vuln_headings:
            fixed_versions = []
            fixed_version = vuln_heading.text.split("Fixed in Apache Tomcat")[-1].strip()
            print("fixed_version = {}".format(fixed_version))

            if "and" in fixed_version:
                # temp_fixed_version = fixed_version.split("and")
                # new_fixed_version = ", ".join(temp_fixed_version)
                # fixed_version = ", ".join(str(e).strip() for e in temp_fixed_version)

                # try this in place of above:
                fixed_versions = fixed_version.split(" and ")
            else:
                fixed_versions.append(fixed_version)

            # if we define fixed_versions immediately above, we don't want this next line:
            # fixed_versions.append(fixed_version)
            print("fixed_versions = {}".format(fixed_versions))

            details_div = vuln_heading.find_next_sibling()

            # =============================== 2022-12-25 Sunday 13:25:12.  Start CVE section experiment

            # We want to start with
            # vuln_p_list = ["Low:", "Moderate:", "Important:", "High:"]
            # if p_tag.text.startswith(tuple(vuln_p_list)):

            vuln_p_list = ["Low:", "Moderate:", "Important:", "High:"]
            # for section in details_div.find_all("p", string=(tuple(vuln_p_list))):
            for section in details_div.find_all("p"):
                # # for subsection in section.find_all("strong", text=(tuple(vuln_p_list))):
                # for subsection in section.find_all(
                #     # "strong", text=lambda text: text and (tuple(vuln_p_list)) in text
                #     "strong",
                #     # this works but tests just 1 value from the list
                #     # text=lambda text: text and "Low:" in text,
                #     # 2022-12-25 Sunday 14:47:23.  Looks like this works!  Though doesn't require startswith . . . .
                #     # text=lambda text: text and any(word in text for word in vuln_p_list),
                #     # TODO: 2022-12-25 Sunday 14:55:09.  This also seems to work at 1st glance and uses startswith!!!
                #     # text=lambda text: text and any(text.startswith(word) for word in vuln_p_list),
                #     # TODO: 2022-12-25 Sunday 15:05:44.  And this also seems to work at 1st glance and also uses startswith!!!
                #     text=lambda text: text and text.startswith(tuple(vuln_p_list)),
                # ):
                #     print(
                #         "\n-----------------------------------------------------------------------------------"
                #     )
                #     print("\nsection = {}\n".format(section))

                #     print("fixed_versions = {}".format(fixed_versions))

                # nextNode = section
                # while True:
                #     # nextNode = nextNode.nextSibling
                #     nextNode = nextNode.find_next_sibling()
                #     try:
                #         tag_name = nextNode.name
                #     except AttributeError:
                #         tag_name = ""
                #         # I want to exclude <strong> but this does not do that:
                #     # if tag_name == "p" and not tag_name.find("strong"):
                #     if tag_name == "p":
                #         print("\nnextNode.string = {}".format(nextNode.string))
                #     else:
                #         # print("*****")
                #         break

                # print(
                #     "\n-----------------------------------------------------------------------------------"
                # )

                # if section.name == "strong":
                #     print("\nHOORAY!\n")

                # # children = section.findChildren("strong", recursive=False)
                # children = section.find_next_sibling("strong")
                # for child in children:
                #     print("\nchild = \n".format(child))

                elements = section.find_all(
                    #     # "strong", text=lambda text: text and (tuple(vuln_p_list)) in text
                    "strong",
                    # this works but tests just 1 value from the list
                    # text=lambda text: text and "Low:" in text,
                    # 2022-12-25 Sunday 14:47:23.  Looks like this works!  Though doesn't require startswith . . . .
                    # text=lambda text: text and any(word in text for word in vuln_p_list),
                    # TODO: 2022-12-25 Sunday 14:55:09.  This also seems to work at 1st glance and uses startswith!!!
                    # text=lambda text: text and any(text.startswith(word) for word in vuln_p_list),
                    # TODO: 2022-12-25 Sunday 15:05:44.  And this also seems to work at 1st glance and also uses startswith!!!
                    text=lambda text: text and text.startswith(tuple(vuln_p_list)),
                )

                for strong_element in elements:

                    # Is this where we want our test_advisory_dict = {}?
                    test_advisory_dict = {}

                    print(
                        "\n-----------------------------------------------------------------------------------"
                    )

                    print("\nfixed_versions = {}".format(fixed_versions))

                    print("\nstrong_element = {}".format(strong_element))
                    print(
                        "\nstrong_element.find_parent() = {}".format(strong_element.find_parent())
                    )

                    severity_score = strong_element.text.split(" ")[0]
                    severity_score = severity_score.split(":")[0]
                    print("\nseverity_score = {}\n".format(severity_score))

                    strong_parent = strong_element.find_parent()

                    cve_url_list = strong_parent.find_all("a")
                    print("cve_url_list = {}\n".format(cve_url_list))

                    cve_id_list = [cve_text.text for cve_text in cve_url_list]
                    print("cve_id_list = {}\n".format(cve_id_list))

                    for cve_url in strong_parent.find_all("a"):
                        print("cve_url = {}\n".format(cve_url))
                        print("cve_url.text = {}".format(cve_url.text))

                    # Extracting all the next siblings of an element
                    # nextSibling = strong_element.find_next_sibling()
                    # nextSiblings = strong_element.find_next_siblings()

                    nextSiblings = strong_parent.find_next_siblings()

                    # Print all the next siblings
                    # print("\nnextSibling = {}".format(nextSibling))

                    # Comment out unless needed -- takes up much terminal output real estate.
                    # print("\nnextSiblings = {}".format(nextSiblings))

                    # 2022-12-25 Sunday 20:05:51.  This might do what we want:
                    for sib in nextSiblings:
                        if "was fixed in" in sib.text or "was fixed with" in sib.text:
                            print("\nnext sib (was fixed) = {}".format(sib))
                            fixed_commit_list = sib.find_all("a")
                            print("\nfixed_commit_list = {}".format(fixed_commit_list))
                        elif "Affects" in sib.text:
                            print("\nnext sib (affects) = {}\n".format(sib))
                            affects_string = sib.text.split("Affects:")[-1].strip()
                            print("affects_string = {}\n".format(affects_string))
                            affected_versions = affects_string.split(",")
                            print("affected_versions = {}\n".format(affected_versions))
                        elif sib.find_all(
                            "strong",
                            text=lambda text: text and text.startswith(tuple(vuln_p_list)),
                        ):
                            break
                        # else:
                        #     print("\nsib.name = {}".format(sib.name))

                    # Starting to flesh out this new approach.
                    for cve_id_record in cve_id_list:
                        test_advisory_dict["fixed_versions"] = fixed_versions
                        test_advisory_dict["aliases"] = [cve_id_record]

                        self.updated_temp_advisory_dict_list.append(test_advisory_dict)

                    print(
                        "-------------------------------------------------------------------------------------\n"
                    )

            # =============================== 2022-12-25 Sunday 13:25:12.  End CVE section experiment

            versions_data = []

            fixed_in_commits = []
            for aa_tag in details_div.find_all("a"):
                if (
                    "was fixed in" in aa_tag.find_parent().text
                    or "was fixed with" in aa_tag.find_parent().text
                ):
                    fixed_in_commits.append(aa_tag["href"])
            print("fixed_in_commits = {}".format(fixed_in_commits))
            # 2022-12-25 Sunday 09:20:55.  ^ This works to some extent -- but we have a duplicate problem when a Fixed-in header (the 'vuln_heading in vuln_headings' loop we're now in) has more than 1 Low/Moderate/High/Important CVE section -- all sections have all fixed in commit References!  Example: 6.0.48.
            # We need to loop through the Low/Moderate/High/Important CVE section, grab the data and build the AvisoryData() object, then do the same for the remaining Low/Moderate/High/Important CVE sections (if any).

            for p_tag in details_div.find_all("p"):
                """
                - We're iterating through a number of sibling <p> elements and want to handle them in groups of related <p> elements.

                - The group of related <p> elements begins with an <h3> element whose text starts with "Fixed in Apache Tomcat" or "Will not be fixed in Apache Tomcat" or "Not fixed in Apache Tomcat" -- that's the `for vuln_heading in vuln_headings:` loop above -- we're inside it now.

                - The <h3> element is followed by a <div> element which contains the full set of sibling <p> elements that we want to divide into groups and handle group-by-group.

                - We're also now inside a child loop of that `vuln_heading` loop -- `for p_tag in details_div.find_all("p"):`.

                - The relevant starting <p> element of each group of related <p> elements begins with "Low:", "Moderate:", "High:" or "Important:".  We want to grab the severity rating that begins that text (e.g., "Low").

                - This text is inside <p><strong><strong><p> and occasionally includes a CVE URL.  In addition, there are 1+ CVE URLs included just before the closing </p> tag.  We want all those CVE URLs

                - We want the URLs (if any) in the <p> elements that list fixing commits -- these either start with "This was fixed" or contain "fixed in".  Some have more than 1 URL.  These will be references and we want all these URLs.

                - We end this group of related sibling <p> elements when we (1) reach the next "Low:/Moderate:/High:/Important:" <p> element or (2) reach the last <p> element in the fixed-version heading -- the end of the "for vuln_heading in vuln_headings:" loop we're currently in.

                - Now we construct the AffectedPackage() object(s) and then the AdvisoryData object

                - If there are more <p> elements to iterate over and group and analyze, we do that next.  If not, we go to the next iteration in the `vuln_heading` loop -- the next fixed-version heading -- and repeat the process.  I think `if not p_tag: continue` might accomplish this.

                """

                cve_id_group = []
                affected_packages = []
                advisory_dict = {}
                severity_score = ""
                severities = []

                affects_versions_data_01 = ""

                if "Affects:" in p_tag.text:
                    affects_versions_data_01 = p_tag.text.split("Affects:")[-1].strip()
                    print("==> affects_versions_data_01 = {}".format(affects_versions_data_01))
                advisory_dict["affected_versions"] = affects_versions_data_01

                # if p_tag.find("strong") and p_tag.find("a"):
                vuln_p_list = ["Low:", "Moderate:", "Important:", "High:"]
                if p_tag.text.startswith(tuple(vuln_p_list)):
                    severity_score = p_tag.text.split(":")[0]
                    # severities.append(severity_score)
                    severities.append(
                        VulnerabilitySeverity(
                            system=GENERIC,
                            value=severity_score,
                            scoring_elements="",
                        )
                    )
                    # print("severity_score = {}".format(severity_score))

                    affects_versions_data_02 = ""

                    if "Affects:" in p_tag.text:
                        affects_versions_data_02 = p_tag.text.split("Affects:")[-1].strip()
                        print("==> affects_versions_data_02 = {}".format(affects_versions_data_02))
                        # ^ This never prints.

                    #     versions_data.append(p_tag.text.split("Affects:")[-1].strip())

                    #     test_versions_data = p_tag.text.split("Affects:")[-1].strip()
                    #     print("==> test_versions_data = {}".format(test_versions_data))

                    jmh_temp_cve_list = []
                    for a_tag in p_tag.find_all("a"):
                        # versions_data = []

                        if "cve.mitre.org" not in a_tag["href"]:
                            # if "fixed in" in p_tag.text:
                            #     fixed_in_commits.append(a_tag["href"])
                            continue
                        cve_id_group.append(re.search(r"CVE-\d*-\d*", a_tag.text).group())

                        cve_id = re.search(r"CVE-\d*-\d*", a_tag.text).group()

                        if "Affects:" in p_tag.text:
                            OG_versions_data = p_tag.text.split("Affects:")[-1].strip()
                            print("==> OG_versions_data = {}".format(OG_versions_data))
                        #     versions_data.append(p_tag.text.split("Affects:")[-1].strip())

                        #     test_versions_data = p_tag.text.split("Affects:")[-1].strip()
                        #     print("==> test_versions_data = {}".format(test_versions_data))

                        print("versions_data = {}".format(versions_data))
                        print("*** affects_versions_data_01 = {}".format(affects_versions_data_01))
                        print("cve_id_group = {}".format(cve_id_group))

                        # print("fixed_in_commits = {}".format(fixed_in_commits))
                        print(
                            "-------------------------------fixed_versions = {}".format(
                                fixed_versions
                            )
                        )

                        # for cve_id in cve_id_group:
                        advisory_dict["aliases"] = [cve_id]
                        advisory_dict["fixed_versions"] = fixed_versions
                        # advisory_dict["affected_versions"] = versions_data
                        advisory_dict["severity_score"] = severity_score

                        self.temp_advisory_dict_list.append(advisory_dict)

                        affected_version_range = self.to_version_ranges(
                            versions_data, fixed_versions
                        )
                        references = [
                            Reference(
                                url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                                reference_id=cve_id,
                                severities=severities,
                            ),
                        ]

                        for commit_url in fixed_in_commits:
                            references.append(Reference(url=commit_url))

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
                                aliases=[cve_id],
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
                # elif "-" in version_item and not any([i.isalpha() for i in version_item]):
                # version_item_split = version_item.split(" ")
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
