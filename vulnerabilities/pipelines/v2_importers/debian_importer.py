#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
from typing import Any
from typing import Iterable
from typing import Mapping

from packageurl import PackageURL
from univers.version_range import DebianVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import create_weaknesses_list
from vulnerabilities.utils import dedupe
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import get_item


class DebianImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Debian Importer Pipeline"""

    pipeline_id = "debian_importer_v2"
    spdx_license_expression = "LicenseRef-scancode-other-permissive"
    license_url = "https://www.debian.org/license"
    notice = """
    From: Tushar Goel <tgoel@nexb.com>
    Date: Thu, May 12, 2022 at 11:42 PM +00:00
    Subject: Usage of Debian Security Data in VulnerableCode
    To: <team@security.debian.org>

    Hey,

    We would like to integrate the debian security data in vulnerablecode
    [1][2] which is a FOSS db of FOSS vulnerability data. We were not able
    to know under which license the debian security data comes. We would
    be grateful to have your acknowledgement over usage of the debian
    security data in vulnerablecode and have some kind of licensing
    declaration from your side.

    [1] - https://github.com/nexB/vulnerablecode
    [2] - https://github.com/nexB/vulnerablecode/pull/723

    Regards,

    From: Moritz Mühlenhoff <jmm@inutil.org>
    Date: Wed, May 17, 2022, 19:12 PM +00:00
    Subject: Re: Usage of Debian Security Data in VulnerableCode
    To: Tushar Goel <tgoel@nexb.com>
    Cc: <team@security.debian.org>


    Am Thu, May 12, 2022 at 05:12:48PM +0530 schrieb Tushar Goel:
    > Hey,
    >
    > We would like to integrate the debian security data in vulnerablecode
    > [1][2] which is a FOSS db of FOSS vulnerability data. We were not able
    > to know under which license the debian security data comes. We would
    > be grateful to have your acknowledgement over usage of the debian
    > security data in vulnerablecode and have some kind of licensing
    > declaration from your side.

    We don't have a specific license, but you have our endorsemen to
    reuse the data by all means :-)

    Cheers,
        Moritz
    """

    api_url = "https://security-tracker.debian.org/tracker/data/json"
    response = None

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    def get_response(self):
        try:
            response = fetch_response(self.api_url)
            if response:
                return response.json()
            return {}
        except Exception as e:
            self.log(f"Error fetching data from {self.api_url!r}: {e}")
            return {}

    def advisories_count(self) -> int:
        adv_count = 0
        if not self.response:
            self.response = self.get_response()
        for pkg in self.response:
            recs = len(self.response[pkg])
            adv_count += recs
        return adv_count

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        if not self.response:
            self.response = self.get_response()
        for pkg_name, records in self.response.items():
            yield from self.parse(pkg_name, records)

    def parse(self, pkg_name: str, records: Mapping[str, Any]) -> Iterable[AdvisoryData]:

        for record_identifier, record in records.items():
            affected_versions = []
            fixed_versions = []

            releases = record["releases"].items()
            for release_name, release_record in releases:
                version = get_item(release_record, "repositories", release_name)

                if not version:
                    self.log(
                        f"Version not found for {release_name} in {record} in package {pkg_name}"
                    )
                    continue

                purl = PackageURL(
                    name=pkg_name,
                    type="deb",
                    namespace="debian",
                    qualifiers={"distro": release_name},
                )

                if release_record.get("status", "") == "resolved":
                    fixed_versions.append(version)
                else:
                    affected_versions.append(version)

                if release_record.get("fixed_version"):
                    fixed_versions.append(release_record["fixed_version"])

            references = []
            debianbug = record.get("debianbug")
            if debianbug:
                bug_url = f"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={debianbug}"
                references.append(ReferenceV2(url=bug_url, reference_id=str(debianbug)))
            affected_versions = dedupe(affected_versions)
            fixed_versions = dedupe(fixed_versions)
            if affected_versions:
                affected_version_range = DebianVersionRange.from_versions(affected_versions)
            else:
                affected_version_range = None
            affected_packages = []
            for fixed_version in fixed_versions:
                affected_packages.append(
                    AffectedPackageV2(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version_range=DebianVersionRange.from_versions([fixed_version]),
                    )
                )
            weaknesses = get_cwe_from_debian_advisory(record)

            yield AdvisoryData(
                advisory_id=f"{pkg_name}/{record_identifier}",
                aliases=[record_identifier],
                summary=record.get("description", ""),
                affected_packages=affected_packages,
                references=references,
                weaknesses=weaknesses,
                url=f"https://security-tracker.debian.org/tracker/{record_identifier}",
            )


def get_cwe_from_debian_advisory(record):
    """
    Extracts CWE ID strings from the given raw_data and returns a list of CWE IDs.

        >>> get_cwe_from_debian_advisory({"description":"PEAR HTML_QuickForm version 3.2.14 contains an eval injection (CWE-95) vulnerability in HTML_QuickForm's getSubmitValue method, HTML_QuickForm's validate method, HTML_QuickForm_hierselect's _setOptions method, HTML_QuickForm_element's _findValue method, HTML_QuickForm_element's _prepareValue method. that can result in Possible information disclosure, possible impact on data integrity and execution of arbitrary code. This attack appear to be exploitable via A specially crafted query string could be utilised, e.g. http://www.example.com/admin/add_practice_type_id[1]=fubar%27])%20OR%20die(%27OOK!%27);%20//&mode=live. This vulnerability appears to have been fixed in 3.2.15."})
        [95]
        >>> get_cwe_from_debian_advisory({"description":"There is no WEAKNESS DATA"})
        []
    """
    description = record.get("description") or ""
    pattern = r"CWE-\d+"
    cwe_strings = re.findall(pattern, description)
    weaknesses = create_weaknesses_list(cwe_strings)
    return weaknesses
