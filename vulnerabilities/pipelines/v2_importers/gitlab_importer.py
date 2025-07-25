#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import logging
import traceback
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Tuple

import pytz
import saneyaml
from dateutil import parser as dateparser
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import VersionRange
from univers.version_range import from_gitlab_native
from univers.versions import Version

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import build_description
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import get_cwe_id


class GitLabImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    GitLab Importer Pipeline

    Collect advisory from GitLab Advisory Database (Open Source Edition).
    """

    pipeline_id = "gitlab_importer_v2"
    spdx_license_expression = "MIT"
    license_url = "https://gitlab.com/gitlab-org/advisories-community/-/blob/main/LICENSE"
    repo_url = "git+https://gitlab.com/gitlab-org/advisories-community/"
    unfurl_version_ranges = True

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    purl_type_by_gitlab_scheme = {
        "conan": "conan",
        "gem": "gem",
        # Entering issue to parse go package names https://github.com/nexB/vulnerablecode/issues/742
        # "go": "golang",
        "maven": "maven",
        "npm": "npm",
        "nuget": "nuget",
        "packagist": "composer",
        "pypi": "pypi",
    }

    gitlab_scheme_by_purl_type = {v: k for k, v in purl_type_by_gitlab_scheme.items()}

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        root = Path(self.vcs_response.dest_dir)
        return sum(1 for _ in root.rglob("*.yml"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_path = Path(self.vcs_response.dest_dir)

        for file_path in base_path.rglob("*.yml"):
            if file_path.parent == base_path:
                continue

            gitlab_type, _, _ = parse_advisory_path(
                base_path=base_path,
                file_path=file_path,
            )

            if gitlab_type not in self.purl_type_by_gitlab_scheme:
                self.log(
                    f"Unknown package type {gitlab_type!r} in {file_path!r}",
                    level=logging.ERROR,
                )
                continue

            advisory = parse_gitlab_advisory(
                file=file_path,
                base_path=base_path,
                gitlab_scheme_by_purl_type=self.gitlab_scheme_by_purl_type,
                purl_type_by_gitlab_scheme=self.purl_type_by_gitlab_scheme,
                logger=self.log,
            )

            if not advisory:
                self.log(
                    f"Failed to parse advisory from {file_path!r}",
                    level=logging.ERROR,
                )
                continue

            yield advisory

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def parse_advisory_path(base_path: Path, file_path: Path) -> Tuple[str, str, str]:
    """
    Parse a gitlab advisory file and return a 3-tuple of:
       (gitlab_type, package_slug, vulnerability_id)

    For example::

    >>> base_path = Path("/tmp/tmpi1klhpmd/checkout")
    >>> file_path=Path("/tmp/tmpi1klhpmd/checkout/pypi/gradio/CVE-2021-43831.yml")
    >>> parse_advisory_path(base_path=base_path, file_path=file_path)
    ('pypi', 'gradio', 'CVE-2021-43831')

    >>> file_path=Path("/tmp/tmpi1klhpmd/checkout/nuget/github.com/beego/beego/v2/nuget/CVE-2021-43831.yml")
    >>> parse_advisory_path(base_path=base_path, file_path=file_path)
    ('nuget', 'github.com/beego/beego/v2/nuget', 'CVE-2021-43831')

    >>> file_path = Path("/tmp/tmpi1klhpmd/checkout/npm/@express/beego/beego/v2/CVE-2021-43831.yml")
    >>> parse_advisory_path(base_path=base_path, file_path=file_path)
    ('npm', '@express/beego/beego/v2', 'CVE-2021-43831')
    """
    relative_path_segments = file_path.relative_to(base_path).parts
    gitlab_type = relative_path_segments[0]
    vuln_id = file_path.stem
    package_slug = "/".join(relative_path_segments[1:-1])

    return gitlab_type, package_slug, vuln_id


def get_purl(package_slug, purl_type_by_gitlab_scheme, logger):
    """
    Return a PackageURL object from a package slug
    """
    parts = [p for p in package_slug.strip("/").split("/") if p]
    gitlab_scheme = parts[0]
    purl_type = purl_type_by_gitlab_scheme.get(gitlab_scheme)
    if not purl_type:
        return
    if gitlab_scheme == "go":
        name = "/".join(parts[1:])
        return PackageURL(type=purl_type, namespace=None, name=name)
    # if package slug is of the form:
    # "nuget/NuGet.Core"
    if len(parts) == 2:
        name = parts[1]
        return PackageURL(type=purl_type, name=name)
    # if package slug is of the form:
    # "nuget/github.com/beego/beego/v2/nuget"
    if len(parts) >= 3:
        name = parts[-1]
        namespace = "/".join(parts[1:-1])
        return PackageURL(type=purl_type, namespace=namespace, name=name)
    logger(f"get_purl: package_slug can not be parsed: {package_slug!r}", level=logging.ERROR)
    return


def extract_affected_packages(
    affected_version_range: VersionRange,
    fixed_versions: List[Version],
    purl: PackageURL,
) -> Iterable[AffectedPackage]:
    """
    Yield AffectedPackage objects, one for each fixed_version

    In case of gitlab advisory data we get a list of fixed_versions and a affected_version_range.
    Since we can not determine which package fixes which range.
    We store the all the fixed_versions with the same affected_version_range in the advisory.
    Later the advisory data is used to be inferred in the GitLabBasicImprover.
    """
    for fixed_version in fixed_versions:
        yield AffectedPackage(
            package=purl,
            fixed_version=fixed_version,
            affected_version_range=affected_version_range,
        )


def parse_gitlab_advisory(
    file, base_path, gitlab_scheme_by_purl_type, purl_type_by_gitlab_scheme, logger
):
    """
    Parse a Gitlab advisory file and return an AdvisoryData or None.
    These files are YAML. There is a JSON schema documented at
    https://gitlab.com/gitlab-org/advisories-community/-/blob/main/ci/schema/schema.json

    Sample YAML file:
    ---
    identifier: "GMS-2018-26"
    package_slug: "packagist/amphp/http"
    title: "Incorrect header injection check"
    description: "amphp/http isn't properly protected against HTTP header injection."
    pubdate: "2018-03-15"
    affected_range: "<1.0.1"
    fixed_versions:
    - "v1.0.1"
    urls:
    - "https://github.com/amphp/http/pull/4"
    cwe_ids:
    - "CWE-1035"
    - "CWE-937"
    identifiers:
    - "GMS-2018-26"
    """
    with open(file) as f:
        gitlab_advisory = saneyaml.load(f)
    if not isinstance(gitlab_advisory, dict):
        logger(
            f"parse_gitlab_advisory: unknown gitlab advisory format in {file!r} with data: {gitlab_advisory!r}",
            level=logging.ERROR,
        )
        return

    # refer to schema here https://gitlab.com/gitlab-org/advisories-community/-/blob/main/ci/schema/schema.json
    aliases = gitlab_advisory.get("identifiers")
    advisory_id = gitlab_advisory.get("identifier")
    package_slug = gitlab_advisory.get("package_slug")
    advisory_id = f"{package_slug}/{advisory_id}" if package_slug else advisory_id
    if advisory_id in aliases:
        aliases.remove(advisory_id)
    summary = build_description(gitlab_advisory.get("title"), gitlab_advisory.get("description"))
    urls = gitlab_advisory.get("urls")
    references = [ReferenceV2.from_url(u) for u in urls]

    cwe_ids = gitlab_advisory.get("cwe_ids") or []
    cwe_list = list(map(get_cwe_id, cwe_ids))

    date_published = dateparser.parse(gitlab_advisory.get("pubdate"))
    date_published = date_published.replace(tzinfo=pytz.UTC)
    advisory_url = get_advisory_url(
        file=file,
        base_path=base_path,
        url="https://gitlab.com/gitlab-org/advisories-community/-/blob/main/",
    )
    purl: PackageURL = get_purl(
        package_slug=package_slug,
        purl_type_by_gitlab_scheme=purl_type_by_gitlab_scheme,
        logger=logger,
    )
    if not purl:
        logger(
            f"parse_yaml_file: purl is not valid: {file!r} {package_slug!r}", level=logging.ERROR
        )
        return AdvisoryData(
            advisory_id=advisory_id,
            aliases=aliases,
            summary=summary,
            references_v2=references,
            date_published=date_published,
            url=advisory_url,
            original_advisory_text=json.dumps(gitlab_advisory, indent=2, ensure_ascii=False),
        )
    affected_version_range = None
    fixed_versions = gitlab_advisory.get("fixed_versions") or []
    affected_range = gitlab_advisory.get("affected_range")
    gitlab_native_schemes = set(["pypi", "gem", "npm", "go", "packagist", "conan"])
    vrc: VersionRange = RANGE_CLASS_BY_SCHEMES[purl.type]
    gitlab_scheme = gitlab_scheme_by_purl_type[purl.type]
    try:
        if affected_range:
            if gitlab_scheme in gitlab_native_schemes:
                affected_version_range = from_gitlab_native(
                    gitlab_scheme=gitlab_scheme, string=affected_range
                )
            else:
                affected_version_range = vrc.from_native(affected_range)
    except Exception as e:
        logger(
            f"parse_yaml_file: affected_range is not parsable: {affected_range!r} for: {purl!s} error: {e!r}\n {traceback.format_exc()}",
            level=logging.ERROR,
        )

    parsed_fixed_versions = []
    for fixed_version in fixed_versions:
        try:
            fixed_version = vrc.version_class(fixed_version)
            parsed_fixed_versions.append(fixed_version)
        except Exception as e:
            logger(
                f"parse_yaml_file: fixed_version is not parsable`: {fixed_version!r} error: {e!r}\n {traceback.format_exc()}",
                level=logging.ERROR,
            )

    if parsed_fixed_versions:
        affected_packages = list(
            extract_affected_packages(
                affected_version_range=affected_version_range,
                fixed_versions=parsed_fixed_versions,
                purl=purl,
            )
        )
    else:
        if not affected_version_range:
            affected_packages = []
        else:
            affected_packages = [
                AffectedPackage(
                    package=purl,
                    affected_version_range=affected_version_range,
                )
            ]
    return AdvisoryData(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=summary,
        references_v2=references,
        date_published=date_published,
        affected_packages=affected_packages,
        weaknesses=cwe_list,
        url=advisory_url,
        original_advisory_text=json.dumps(gitlab_advisory, indent=2, ensure_ascii=False),
    )
