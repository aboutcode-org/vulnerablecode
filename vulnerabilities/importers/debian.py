#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import logging
from typing import Any
from typing import Iterable
from typing import List
from typing import Mapping

import requests
from django.db.models.query import QuerySet
from packageurl import PackageURL
from univers.version_range import DebianVersionRange
from univers.versions import DebianVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import UnMergeablePackageError
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.utils import AffectedPackage as LegacyAffectedPackage
from vulnerabilities.utils import dedupe
from vulnerabilities.utils import get_affected_packages_by_patched_package
from vulnerabilities.utils import get_item
from vulnerabilities.utils import nearest_patched_package

logger = logging.getLogger(__name__)


class DebianImporter(Importer):

    spdx_license_expression = "MIT"
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

    def get_response(self):
        response = requests.get(self.api_url)
        if response.status_code == 200:
            return response.json()
        raise Exception(
            f"Failed to fetch data from {self.api_url!r} with status code: {response.status_code!r}"
        )

    def advisory_data(self) -> Iterable[AdvisoryData]:
        response = self.get_response()
        for pkg_name, records in response.items():
            yield from self.parse(pkg_name, records)

    def parse(self, pkg_name: str, records: Mapping[str, Any]) -> Iterable[AdvisoryData]:
        for cve_id, record in records.items():
            affected_versions = []
            fixed_versions = []
            if not cve_id.startswith("CVE"):
                logger.error(f"Invalid CVE ID: {cve_id} in {record} in package {pkg_name}")
                continue

            # vulnerabilities starting with something else may not be public yet
            # see for instance https://web.archive.org/web/20201215213725/https://security-tracker.debian.org/tracker/TEMP-0000000-A2EB44
            # TODO: this would need to be revisited though to ensure we are not missing out on anything
            # https://github.com/nexB/vulnerablecode/issues/730

            releases = record["releases"].items()
            for release_name, release_record in releases:
                version = get_item(release_record, "repositories", release_name)

                if not version:
                    logger.error(
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

                if "fixed_version" in release_record:
                    fixed_versions.append(release_record["fixed_version"])

            references = []
            debianbug = record.get("debianbug")
            if debianbug:
                bug_url = f"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={debianbug}"
                references.append(Reference(url=bug_url, reference_id=str(debianbug)))
            affected_versions = dedupe(affected_versions)
            fixed_versions = dedupe(fixed_versions)
            if affected_versions:
                affected_version_range = DebianVersionRange.from_versions(affected_versions)
            else:
                affected_version_range = None
            affected_packages = []
            for fixed_version in fixed_versions:
                affected_packages.append(
                    AffectedPackage(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version=DebianVersion(fixed_version),
                    )
                )
            yield AdvisoryData(
                aliases=[cve_id],
                summary=record.get("description", ""),
                affected_packages=affected_packages,
                references=references,
            )


class DebianBasicImprover(Improver):
    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(created_by=DebianImporter.qualified_name)

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        """
        Yield Inferences for the given advisory data
        """
        if not advisory_data.affected_packages:
            return
        try:
            purl, affected_version_ranges, fixed_versions = AffectedPackage.merge(
                advisory_data.affected_packages
            )
        except UnMergeablePackageError:
            logger.error(f"Cannot merge with different purls {advisory_data.affected_packages!r}")
            return

        pkg_type = purl.type
        pkg_namespace = purl.namespace
        pkg_name = purl.name
        pkg_qualifiers = purl.qualifiers
        fixed_purls = [
            PackageURL(
                type=pkg_type,
                namespace=pkg_namespace,
                name=pkg_name,
                version=str(version),
                qualifiers=pkg_qualifiers,
            )
            for version in fixed_versions
        ]
        if not affected_version_ranges:
            for fixed_purl in fixed_purls:
                yield Inference.from_advisory_data(
                    advisory_data,  # We are getting all valid versions to get this inference
                    confidence=MAX_CONFIDENCE,
                    affected_purls=[],
                    fixed_purl=fixed_purl,
                )
        else:
            aff_versions = set()
            for affected_version_range in affected_version_ranges:
                for constraint in affected_version_range.constraints:
                    aff_versions.add(constraint.version.string)
            affected_purls = [
                PackageURL(
                    type=pkg_type,
                    namespace=pkg_namespace,
                    name=pkg_name,
                    version=version,
                    qualifiers=pkg_qualifiers,
                )
                for version in aff_versions
            ]
            affected_packages: List[LegacyAffectedPackage] = nearest_patched_package(
                vulnerable_packages=affected_purls, resolved_packages=fixed_purls
            )

            for (fixed_package, affected_packages,) in get_affected_packages_by_patched_package(
                affected_packages=affected_packages
            ).items():
                yield Inference.from_advisory_data(
                    advisory_data,
                    confidence=MAX_CONFIDENCE,  # We are getting all valid versions to get this inference
                    affected_purls=affected_packages,
                    fixed_purl=fixed_package,
                )
