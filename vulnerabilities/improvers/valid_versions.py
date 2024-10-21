#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses
import logging
from datetime import datetime
from typing import Iterable
from typing import List
from typing import Optional

from django.db.models import Q
from django.db.models.query import QuerySet
from fetchcode import package_versions
from packageurl import PackageURL
from univers.versions import NginxVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import UnMergeablePackageError
from vulnerabilities.importers.apache_httpd import ApacheHTTPDImporter
from vulnerabilities.importers.apache_kafka import ApacheKafkaImporter
from vulnerabilities.importers.apache_tomcat import ApacheTomcatImporter
from vulnerabilities.importers.curl import CurlImporter
from vulnerabilities.importers.debian import DebianImporter
from vulnerabilities.importers.debian_oval import DebianOvalImporter
from vulnerabilities.importers.elixir_security import ElixirSecurityImporter
from vulnerabilities.importers.github_osv import GithubOSVImporter
from vulnerabilities.importers.istio import IstioImporter
from vulnerabilities.importers.oss_fuzz import OSSFuzzImporter
from vulnerabilities.importers.ruby import RubyImporter
from vulnerabilities.importers.ubuntu import UbuntuImporter
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.pipelines.github_importer import GitHubAPIImporterPipeline
from vulnerabilities.pipelines.gitlab_importer import GitLabImporterPipeline
from vulnerabilities.pipelines.nginx_importer import NginxImporterPipeline
from vulnerabilities.pipelines.npm_importer import NpmImporterPipeline
from vulnerabilities.utils import AffectedPackage as LegacyAffectedPackage
from vulnerabilities.utils import clean_nginx_git_tag
from vulnerabilities.utils import get_affected_packages_by_patched_package
from vulnerabilities.utils import is_vulnerable_nginx_version
from vulnerabilities.utils import nearest_patched_package
from vulnerabilities.utils import resolve_version_range
from vulnerabilities.utils import update_purl_version

logger = logging.getLogger(__name__)


@dataclasses.dataclass(order=True, init=False)
class ValidVersionImprover(Improver):
    importer: Importer
    ignorable_versions: List[str] = dataclasses.field(default_factory=list)

    @property
    def interesting_advisories(self) -> QuerySet:
        if issubclass(self.importer, VulnerableCodeBaseImporterPipeline):
            return Advisory.objects.filter(Q(created_by=self.importer.pipeline_id)).paginated()
        return Advisory.objects.filter(Q(created_by=self.importer.qualified_name)).paginated()

    def get_package_versions(
        self, package_url: PackageURL, until: Optional[datetime] = None
    ) -> List[str]:
        """
        Return a list of versions published before `until` for the `package_url`
        """
        versions = package_versions.versions(str(package_url))
        versions_before_until = []
        for version in versions or []:
            if until and version.release_date and version.release_date > until:
                continue
            versions_before_until.append(version.value)

        return versions_before_until

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        """
        Yield Inferences for the given advisory data
        """
        mergable = True
        if not advisory_data.affected_packages:
            return

        try:
            purl, affected_version_ranges, fixed_versions = AffectedPackage.merge(
                advisory_data.affected_packages
            )
        except UnMergeablePackageError:
            logger.error(f"Cannot merge with different purls {advisory_data.affected_packages!r}")
            mergable = False

        if not mergable:
            for affected_package in advisory_data.affected_packages:
                purl = affected_package.package
                affected_version_range = affected_package.affected_version_range
                fixed_version = affected_package.fixed_version
                pkg_type = purl.type
                pkg_namespace = purl.namespace
                pkg_name = purl.name
                if not affected_version_range and fixed_version:
                    yield Inference.from_advisory_data(
                        advisory_data,  # We are getting all valid versions to get this inference
                        confidence=MAX_CONFIDENCE,
                        affected_purls=[],
                        fixed_purl=PackageURL(
                            type=pkg_type,
                            namespace=pkg_namespace,
                            name=pkg_name,
                            version=str(fixed_version),
                        ),
                    )
                else:
                    valid_versions = self.get_package_versions(
                        package_url=purl, until=advisory_data.date_published
                    )
                    yield from self.generate_inferences(
                        affected_version_range=affected_version_range,
                        pkg_type=pkg_type,
                        pkg_namespace=pkg_namespace,
                        pkg_name=pkg_name,
                        valid_versions=valid_versions,
                        advisory_data=advisory_data,
                    )

        else:
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
                for fixed_purl in fixed_purls or []:
                    yield Inference.from_advisory_data(
                        advisory_data,  # We are getting all valid versions to get this inference
                        confidence=MAX_CONFIDENCE,
                        affected_purls=[],
                        fixed_purl=fixed_purl,
                    )
            else:
                valid_versions = self.get_package_versions(
                    package_url=purl, until=advisory_data.date_published
                )
                for affected_version_range in affected_version_ranges:
                    yield from self.generate_inferences(
                        affected_version_range=affected_version_range,
                        pkg_type=pkg_type,
                        pkg_namespace=pkg_namespace,
                        pkg_name=pkg_name,
                        valid_versions=valid_versions,
                        advisory_data=advisory_data,
                    )

    def generate_inferences(
        self,
        affected_version_range,
        pkg_type,
        pkg_namespace,
        pkg_name,
        valid_versions,
        advisory_data,
    ):
        """
        Generate Inferences for the given `affected_version_range` and `valid_versions`
        """
        aff_vers, unaff_vers = resolve_version_range(
            affected_version_range=affected_version_range,
            ignorable_versions=self.ignorable_versions,
            package_versions=valid_versions,
        )

        affected_purls = list(
            self.expand_verion_range_to_purls(pkg_type, pkg_namespace, pkg_name, aff_vers)
        )

        unaffected_purls = list(
            self.expand_verion_range_to_purls(pkg_type, pkg_namespace, pkg_name, unaff_vers)
        )

        affected_packages: List[LegacyAffectedPackage] = nearest_patched_package(
            vulnerable_packages=affected_purls, resolved_packages=unaffected_purls
        )

        for (
            fixed_package,
            affected_purls,
        ) in get_affected_packages_by_patched_package(affected_packages).items():
            yield Inference.from_advisory_data(
                advisory_data,
                confidence=100,  # We are getting all valid versions to get this inference
                affected_purls=affected_purls,
                fixed_purl=fixed_package,
            )

    def expand_verion_range_to_purls(self, pkg_type, pkg_namespace, pkg_name, versions):
        for version in versions:
            yield PackageURL(type=pkg_type, namespace=pkg_namespace, name=pkg_name, version=version)


class NginxBasicImprover(Improver):
    """
    Improve Nginx data by fetching the its GitHub repo versions and resolving
    the vulnerable ranges.
    """

    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(created_by=NginxImporterPipeline.pipeline_id).paginated()

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        all_versions = list(self.fetch_nginx_version_from_git_tags())
        yield from self.get_inferences_from_versions(
            advisory_data=advisory_data, all_versions=all_versions
        )

    def get_inferences_from_versions(
        self, advisory_data: AdvisoryData, all_versions: List[str]
    ) -> Iterable[Inference]:
        """
        Yield inferences given an ``advisory_data`` and a ``all_versions``.
        """

        try:
            purl, affected_version_ranges, fixed_versions = AffectedPackage.merge(
                advisory_data.affected_packages
            )
        except UnMergeablePackageError:
            logger.error(
                f"NginxBasicImprover: Cannot merge with different purls: "
                f"{advisory_data.affected_packages!r}"
            )
            return iter([])

        affected_purls = []
        for affected_version_range in affected_version_ranges:
            for version in all_versions:
                # FIXME: we should reference an NginxVersion tbd in univers
                version = NginxVersion(version)
                if is_vulnerable_nginx_version(
                    version=version,
                    affected_version_range=affected_version_range,
                    fixed_versions=fixed_versions,
                ):
                    new_purl = update_purl_version(purl=purl, version=str(version))
                    affected_purls.append(new_purl)

        # TODO: This also yields with a lower fixed version, maybe we should
        # only yield fixes that are upgrades ?
        for fixed_version in fixed_versions:
            fixed_purl = update_purl_version(purl=purl, version=str(fixed_version))

            yield Inference.from_advisory_data(
                advisory_data,
                # TODO: is 90 a correct confidence??
                confidence=90,
                affected_purls=affected_purls,
                fixed_purl=fixed_purl,
            )

    def fetch_nginx_version_from_git_tags(self):
        """
        Yield all nginx version from its git tags.
        """
        nginx_versions = package_versions.versions("pkg:github/nginx/nginx")
        for version in nginx_versions or []:
            cleaned = clean_nginx_git_tag(version.value)
            yield cleaned


class ApacheHTTPDImprover(ValidVersionImprover):
    importer = ApacheHTTPDImporter
    ignorable_versions = {
        "AGB_BEFORE_AAA_CHANGES",
        "APACHE_1_2b1",
        "APACHE_1_2b10",
        "APACHE_1_2b11",
        "APACHE_1_2b2",
        "APACHE_1_2b3",
        "APACHE_1_2b4",
        "APACHE_1_2b5",
        "APACHE_1_2b6",
        "APACHE_1_2b7",
        "APACHE_1_2b8",
        "APACHE_1_2b9",
        "APACHE_1_3_PRE_NT",
        "APACHE_1_3a1",
        "APACHE_1_3b1",
        "APACHE_1_3b2",
        "APACHE_1_3b3",
        "APACHE_1_3b5",
        "APACHE_1_3b6",
        "APACHE_1_3b7",
        "APACHE_2_0_2001_02_09",
        "APACHE_2_0_52_WROWE_RC1",
        "APACHE_2_0_ALPHA",
        "APACHE_2_0_ALPHA_2",
        "APACHE_2_0_ALPHA_3",
        "APACHE_2_0_ALPHA_4",
        "APACHE_2_0_ALPHA_5",
        "APACHE_2_0_ALPHA_6",
        "APACHE_2_0_ALPHA_7",
        "APACHE_2_0_ALPHA_8",
        "APACHE_2_0_ALPHA_9",
        "APACHE_2_0_BETA_CANDIDATE_1",
        "APACHE_BIG_SYMBOL_RENAME_POST",
        "APACHE_BIG_SYMBOL_RENAME_PRE",
        "CHANGES",
        "HTTPD_LDAP_1_0_0",
        "INITIAL",
        "MOD_SSL_2_8_3",
        "PCRE_3_9",
        "POST_APR_SPLIT",
        "PRE_APR_CHANGES",
        "STRIKER_2_0_51_RC1",
        "STRIKER_2_0_51_RC2",
        "STRIKER_2_1_0_RC1",
        "WROWE_2_0_43_PRE1",
        "apache-1_3-merge-1-post",
        "apache-1_3-merge-1-pre",
        "apache-1_3-merge-2-post",
        "apache-1_3-merge-2-pre",
        "apache-apr-merge-3",
        "apache-doc-split-01",
        "dg_last_1_2_doc_merge",
        "djg-apache-nspr-07",
        "djg_nspr_split",
        "moving_to_httpd_module",
        "mpm-3",
        "mpm-merge-1",
        "mpm-merge-2",
        "post_ajp_proxy",
        "pre_ajp_proxy",
    }


class ApacheTomcatImprover(ValidVersionImprover):
    importer = ApacheTomcatImporter
    ignorable_versions = []


class ApacheKafkaImprover(ValidVersionImprover):
    importer = ApacheKafkaImporter
    ignorable_versions = []


class DebianBasicImprover(ValidVersionImprover):
    importer = DebianImporter
    ignorable_versions = []


class GitLabBasicImprover(ValidVersionImprover):
    importer = GitLabImporterPipeline
    ignorable_versions = []


class GitHubBasicImprover(ValidVersionImprover):
    importer = GitHubAPIImporterPipeline
    ignorable_versions = frozenset(
        [
            "0.1-bulbasaur",
            "0.1-charmander",
            "0.3m1",
            "0.3m2",
            "0.3m3",
            "0.3m4",
            "0.3m5",
            "0.4m1",
            "0.4m2",
            "0.4m3",
            "0.4m4",
            "0.4m5",
            "0.5m1",
            "0.5m2",
            "0.5m3",
            "0.5m4",
            "0.5m5",
            "0.6m1",
            "0.6m2",
            "0.6m3",
            "0.6m4",
            "0.6m5",
            "0.6m6",
            "0.7.10p1",
            "0.7.11p1",
            "0.7.11p2",
            "0.7.11p3",
            "0.8.1p1",
            "0.8.3p1",
            "0.8.4p1",
            "0.8.4p2",
            "0.8.6p1",
            "0.8.7p1",
            "0.9-doduo",
            "0.9-eevee",
            "0.9-fearow",
            "0.9-gyarados",
            "0.9-horsea",
            "0.9-ivysaur",
            "2013-01-21T20:33:09+0100",
            "2013-01-23T17:11:52+0100",
            "2013-02-01T20:50:46+0100",
            "2013-02-02T19:59:03+0100",
            "2013-02-02T20:23:17+0100",
            "2013-02-08T17:40:57+0000",
            "2013-03-27T16:32:26+0100",
            "2013-05-09T12:47:53+0200",
            "2013-05-10T17:55:56+0200",
            "2013-05-14T20:16:05+0200",
            "2013-06-01T10:32:51+0200",
            "2013-07-19T09:11:08+0000",
            "2013-08-12T21:48:56+0200",
            "2013-09-11T19-27-10",
            "2013-12-23T17-51-15",
            "2014-01-12T15-52-10",
            "2.0.1rc2-git",
            "3.0.0b3-",
            "3.0b6dev-r41684",
            "-class.-jw.util.version.Version-",
            "vulnerabilities",
        ]
    )


class NpmImprover(ValidVersionImprover):
    importer = NpmImporterPipeline
    ignorable_versions = []


class ElixirImprover(ValidVersionImprover):
    importer = ElixirSecurityImporter
    ignorable_versions = []


class IstioImprover(ValidVersionImprover):
    importer = IstioImporter
    ignorable_versions = []


class DebianOvalImprover(ValidVersionImprover):
    importer = DebianOvalImporter
    ignorable_versions = []


class UbuntuOvalImprover(ValidVersionImprover):
    importer = UbuntuImporter
    ignorable_versions = []


class OSSFuzzImprover(ValidVersionImprover):
    importer = OSSFuzzImporter
    ignorable_versions = []


class RubyImprover(ValidVersionImprover):
    importer = RubyImporter
    ignorable_versions = []


class GithubOSVImprover(ValidVersionImprover):
    importer = GithubOSVImporter
    ignorable_versions = []


class CurlImprover(ValidVersionImprover):
    importer = CurlImporter
    ignorable_versions = []
