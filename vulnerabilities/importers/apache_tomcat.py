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

TRACE = True

record_of_all_affects_elements = []
record_of_all_affected_versions = []
record_of_all_reported_cves = []


# Not yet finished!
corrective_data_mapping = {
    (("4.1.3",), "CVE-2002-0935"): {
        "fixed_versions": ["4.1.3"],
        "affected_versions": ["4.0.0-4.0.2", "4.0.3", "4.0.4-4.0.6", "4.1.0-4.1.2"],
    },
}


class ApacheTomcatImporter(Importer):

    spdx_license_expression = "Apache-2.0"
    license_url = "https://www.apache.org/licenses/"

    # temp_list_of_fixed_versions = []
    # temp_advisory_dict_list = []
    # updated_temp_advisory_dict_list = []
    # record_of_all_affects_elements = []
    # record_of_all_affects_strings = []
    # record_of_all_affected_version_strings = []

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

        # for advisory_page in self.fetch_advisory_pages(self.security_updates_home):
        for advisory_page in self.fetch_advisory_pages():
            advisories.extend(self.extract_advisories_from_page(advisory_page))

        if TRACE:
            self.debug_advisory_data(advisories)

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

        # record_of_all_reported_cves
        tomcat_reported_cves = "vulnerabilities/tests/test_data/apache_tomcat/trace/record_of_all_reported_cves-2023-01-04-00.txt"
        with open(tomcat_reported_cves, "w") as f:
            for line in record_of_all_reported_cves:
                f.write(f"{line}\n")

        # apache_tomcat_advisories = "apache_tomcat_advisories_refactored-02.txt"

        # with open(apache_tomcat_advisories, "w") as f:
        #     for advisory in advisories:
        #         f.write(f"{advisory}\n")

        # temp_advisory_to_dict_list = []
        # for adv in advisories:
        #     adv_dict = adv.to_dict()
        #     temp_advisory_to_dict_list.append(adv_dict)

        # with open(
        #     "apache_tomcat_advisories_to_dict-02.json",
        #     "w",
        #     encoding="utf-8",
        # ) as f:
        #     json.dump(temp_advisory_to_dict_list, f, ensure_ascii=False, indent=4)

        # with open(
        #     "apache_tomcat_fixed_version_list-00.txt",
        #     "w",
        # ) as f:
        #     for line in self.temp_list_of_fixed_versions:
        #         f.write(f"{line}\n")

        # with open(
        #     "apache_tomcat_advisory_dict_list-00.json",
        #     "w",
        #     encoding="utf-8",
        # ) as f:
        #     json.dump(self.temp_advisory_dict_list, f, ensure_ascii=False, indent=4)

        # with open(
        #     "apache_tomcat_advisory_dict_list-00-updated.json",
        #     "w",
        #     encoding="utf-8",
        # ) as f:
        #     json.dump(self.updated_temp_advisory_dict_list, f, ensure_ascii=False, indent=4)

        # tomcat_affects_elements = "vulnerabilities/tests/test_data/apache_tomcat/record_of_all_affects_elements-2023-01-03-00.txt"
        # with open(tomcat_affects_elements, "w") as f:
        #     for line in self.record_of_all_affects_elements:
        #         f.write(f"{line}\n")

        # tomcat_affects_strings = "record_of_all_affects_strings-2022-12-27-00.txt"
        # with open(tomcat_affects_strings, "w") as f:
        #     for line in self.record_of_all_affects_strings:
        #         f.write(f"{line}\n")

        # tomcat_affected_version_strings = "record_of_all_affected_version_strings-2022-12-27-00.txt"
        # with open(tomcat_affected_version_strings, "w") as f:
        #     for line in self.record_of_all_affected_version_strings:
        #         f.write(f"{line}\n")

    def extract_advisories_from_page(self, apache_tomcat_advisory_html):
        """
        Return a list of AdvisoryData extracted from the HTML text ``apache_tomcat_advisory_html``.
        """
        advisories = []

        test_output = extract_tomcat_advisory_data_from_page(apache_tomcat_advisory_html)

        for adv in test_output:
            advisory_data_objects = generate_advisory_data_objects(adv)

            for advisory_data_object in advisory_data_objects:
                print("\nadvisory_data_object = {}\n".format(advisory_data_object))
                # to_dict()
                print(
                    "\nadvisory_data_object.to_dict() = {}\n".format(advisory_data_object.to_dict())
                )

                adv_dict = advisory_data_object.to_dict()
                print(json.dumps(adv_dict, indent=4, sort_keys=False))
                # XXX: 2023-01-05 Thursday 09:18:15.  Great this now works w/o the error
                # TypeError: Object of type Tag is not JSON serializable

                # result = advisory_data_object.to_dict()
                # print(json.dumps(result, indent=4, sort_keys=False))

            # # another to_dict() approach:
            # another_result = [data.to_dict() for data in advisory_data_objects]
            # print(another_result)
            # print("another_result = \n")
            # print(json.dumps(another_result, indent=4, sort_keys=False))

            advisories.append(advisory_data_objects)

        return advisories


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


def extract_tomcat_advisory_data_from_page(apache_tomcat_advisory_html):
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
        print("\n==================================================\n")
        print("*** fixed_version_heading.text = {} ***".format(fixed_version_heading.text))
        fixed_versions = []
        fixed_version = fixed_version_heading.text.split("Fixed in Apache Tomcat")[-1].strip()

        # if TRACE:
        #     print("fixed_version = {}".format(fixed_version))
        #     print("===========================")

        # We want to handle the occasional "and" in the fixed version headers, e.g.,
        # <h3 id="Fixed_in_Apache_Tomcat_8.5.5_and_8.0.37"><span class="pull-right">5 September 2016</span> Fixed in Apache Tomcat 8.5.5 and 8.0.37</h3>
        if " and " in fixed_version:
            fixed_versions = fixed_version.split(" and ")
        else:
            fixed_versions.append(fixed_version)

        print("*** fixed_versions = {} ***\n".format(fixed_versions))

        # if TRACE:
        #     print("fixed_versions = {}".format(fixed_versions))
        # print("===========================")

        # Each group of fixed-version-related data is contained in a div that immediately follows the h3 element, e.g.,
        # <h3 id="Fixed_in_Apache_Tomcat_8.5.8"><span class="pull-right">8 November 2016</span> Fixed in Apache Tomcat 8.5.8</h3>
        # <div class="text"> ... <div>
        fixed_version_paras = fixed_version_heading.find_next_sibling()

        # See https://tomcat.apache.org/security-impact.html for scoring.
        # Each advisory section starts with a <p> element,
        # the text of which starts with, e.g., "Low:", so we look for these here, e.g.,
        # <p><strong>Low: Apache Tomcat request smuggling</strong><a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-42252" rel="nofollow">CVE-2022-42252</a></p>
        # severities = ("Low:", "Moderate:", "Important:", "High:", "Critical:")
        severity_scores = ("Low:", "Moderate:", "Important:", "High:", "Critical:")
        # A list of groups of paragraphs, each for a single Tomcat Advisory.
        advisory_groups = []

        for para in fixed_version_paras.find_all("p"):
            current_group = []
            if para.text.startswith(severity_scores):
                current_group.append(para)

                # TODO: 2023-01-02 Monday 11:47:58.  Rename this `nextSiblings`.
                test_nextSiblings = para.find_next_siblings()
                for next_sibling in test_nextSiblings:
                    if not next_sibling.text.startswith(severity_scores):
                        current_group.append(next_sibling)
                    elif next_sibling.text.startswith(severity_scores):
                        break

                advisory_groups.append(current_group)

        # if TRACE:
        #     print("\ncurrent_group = {}\n".format(current_group))
        #     print("\nadvisory_groups = {}\n".format(advisory_groups))

        yield TomcatAdvisoryData(fixed_versions=fixed_versions, advisory_groups=advisory_groups)


def generate_advisory_data_objects(tomcat_advisory_data_object):

    fixed_versions = tomcat_advisory_data_object.fixed_versions

    # len_advisory_groups = len(tomcat_advisory_data_object.advisory_groups)
    # print("\nlen_advisory_groups = {}\n".format(len_advisory_groups))

    # aliases = []

    # vuln_p_list = ("Low:", "Moderate:", "Important:", "High:", "Critical:")
    # severities = ("Low:", "Moderate:", "Important:", "High:", "Critical:")
    severity_scores = ("Low:", "Moderate:", "Important:", "High:", "Critical:")

    for para_list in tomcat_advisory_data_object.advisory_groups:
        # XXX: 2023-01-02 Monday 12:15:49.  Hide but keep while debugging
        # print("type(para_list) = {}".format(type(para_list)))
        # print("\npara_list = {}\n".format(para_list))
        affected_versions = []
        fixed_commit_list = []
        references = []
        cve_url_list = []
        for para in para_list:

            if para.text.startswith("Affects:"):
                # 2023-01-03 Tuesday 20:33:02.  Add to .txt
                record_of_all_affects_elements.append(para.text)
                # print("\npara startswith Affects: = {}\n".format(para))
                # print(">>> {}".format(para.text.split(":")[-1]))
                # This will need detailed cleaning:

                print("\npara.text startswith affects = {}".format(para.text))

                formatted_affected_version_data = para.text.split(":")[-1].split(", ")
                print(
                    "\nformatted_affected_version_data = {}\n".format(
                        formatted_affected_version_data
                    )
                )

                # affected_versions.append(para.text.split(":")[-1])
                affected_versions.extend(formatted_affected_version_data)

                print("\naffected_versions = {}".format(affected_versions))

                # # XXX: Remove any leading spaces
                # affected_versions = [
                #     affected_version.strip() for affected_version in affected_versions
                # ]
            elif "was fixed in" in para.text or "was fixed with" in para.text:
                # XXX: 2023-01-02 Monday 12:15:49.  Hide but keep while debugging
                # print("\nnext sib (was fixed) = {}".format(para))
                fixed_commit_list = para.find_all("a")
                print("\nfixed_commit_list = {}\n".format(fixed_commit_list))

                # print("\n!!!!!!!!! fixed_commit_list = {}\n".format(fixed_commit_list))
                references.extend([ref_url["href"] for ref_url in fixed_commit_list])
            elif para.text.startswith(severity_scores):
                # XXX: 2023-01-02 Monday 12:15:49.  Hide but keep while debugging
                # print("\n==> para_severity_row = {}\n".format(para))
                cve_url_list = para.find_all("a")
                # print("==> cve_url_list = {}".format(cve_url_list))
                cve_list = [cve_url.text for cve_url in cve_url_list]
                print("\n==> cve_list = {}".format(cve_list))

                severity_score = para.text.split(":")[0]

        for cve_url in cve_url_list:
            print("\n^^^ cve_url = {}\n".format(cve_url))
            aliases = []
            aliases.append(cve_url.text)

            # better_severities = []
            severity_list = []
            severity_list.append(
                VulnerabilitySeverity(
                    system=APACHE_TOMCAT,
                    value=severity_score,
                    scoring_elements="",
                )
            )

            # FIXME: 2023-01-05 Thursday 12:05:16.  Check the dictionary and supply/replace needed values.
            # Convert the list `fixed_versions`` to a tuple so it's hashable and thus can serve as part of a tuple-based dictionary key.
            print("fixed_versions before update if any = {}".format(fixed_versions))
            print("affected_versions before update if any = {}\n".format(affected_versions))

            fixed_versions_tuple = tuple(fixed_versions)

            if (fixed_versions_tuple, cve_url.text) in corrective_data_mapping.keys():
                print("\n\n-- REPLACE/CORRECT VERSION DATA --  \n\n")
                fixed_versions = corrective_data_mapping[fixed_versions_tuple, cve_url.text][
                    "fixed_versions"
                ]
                affected_versions = corrective_data_mapping[fixed_versions_tuple, cve_url.text][
                    "affected_versions"
                ]
            else:
                pass

            print("==> reported_cve = {}\n".format(cve_url.text))
            record_of_all_reported_cves.append(cve_url.text)

            # print("==> affected_versions = {}".format(affected_versions))
            print("fixed_versions after update if any = {}".format(fixed_versions))
            print("affected_versions after update if any = {}".format(affected_versions))

            # # XXX: Do we want to remove leading spaces here?  Can we do this earlier?
            # print(
            #     "==> affected_versions -- stripped = {}".format(
            #         [affected_version.strip() for affected_version in affected_versions]
            #     )
            # )
            record_of_all_affected_versions.append(affected_versions)

            # XXX: 2023-01-02 Monday 15:02:15.  We need to clean up the affected version data
            # with a combination of RegEx, replace(), join()/split() and split().

            # XXX: 2023-01-02 Monday 14:46:15.  Remove `self.`
            # affected_version_range = self.to_version_ranges(
            affected_version_range = to_version_ranges(
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
                    # XXX: 2023-01-02 Monday 14:56:33.  We want to use cve_url in this current loop.
                    # url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={better_cve_id_record}",
                    # url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_url}",
                    # XXX: 2023-01-05 Thursday 09:05:10.  Is above throwing error when I try json.dumps()?
                    # We want this instead:
                    url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_url.text}",
                    # # reference_id=cve_id,
                    # # reference_id=better_cve_id_record,
                    # reference_id=cve_url,
                    # XXX: 2023-01-05 Thursday 09:15:31.  Or maybe the above is throwing the error
                    # TypeError: Object of type Tag is not JSON serializable
                    # so instead just get the text, e.g., CVE-2020-1234, not the entire <a> tag?
                    # 2023-01-05 Thursday 09:18:50.  YES this removed the error and json.dumps()
                    # now works above in extract_advisories_from_page.  Excellent!
                    reference_id=cve_url.text,
                    # severities=severities,
                    severities=severity_list,
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

            #     advisories.append(
            #         AdvisoryData(
            #             aliases=[better_cve_id_record],
            #             summary="",
            #             affected_packages=affected_packages,
            #             references=references,
            #         )
            #     )

            # self.temp_list_of_fixed_versions.append(fixed_versions)

            yield AdvisoryData(
                aliases=aliases,
                summary="",
                affected_packages=affected_packages,
                references=references,
            )


# XXX: 2023-01-02 Monday 14:52:31.  This is converted from a method function because it's
# now called by another independent function and thus has no `self`.
def to_version_ranges(versions_data, fixed_versions):
    constraints = []

    for version_item in versions_data:
        # XXX: 2023-01-02 Monday 15:12:36.  Clean affected version data here or above
        # in generate_advisory_data_objects()?  Try here.
        # print("version_item = {}".format(version_item))
        version_item = version_item.strip()
        # print("version_item.strip() = {}".format(version_item.strip()))
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

    # XXX: 2023-01-02 Monday 14:58:47.  Need to check whether the inverted value is
    # already in the `constraints` list.
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
