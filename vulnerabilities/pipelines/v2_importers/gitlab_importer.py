#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from pathlib import Path
from typing import Iterable
from typing import Tuple

import saneyaml
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipelines.v2_importers.gitlab_advisory_utils import (
    advisory_dict_to_advisory_data as shared_advisory_dict_to_advisory_data,
)
from vulnerabilities.utils import get_advisory_url


class GitLabImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    GitLab Importer Pipeline

    Collect advisory from GitLab Advisory Database (Open Source Edition).
    """

    pipeline_id = "gitlab_importer_v2"
    spdx_license_expression = "MIT"
    license_url = "https://gitlab.com/gitlab-org/advisories-community/-/blob/main/LICENSE"
    repo_url = "git+https://gitlab.com/gitlab-org/advisories-community/"

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

    # Build a stable URL to the advisory file within the repo for traceability
    advisory_url = get_advisory_url(
        file=file,
        base_path=base_path,
        url="https://gitlab.com/gitlab-org/advisories-community/-/blob/main/",
    )

    return shared_advisory_dict_to_advisory_data(
        advisory=gitlab_advisory,
        purl_type_by_gitlab_scheme=purl_type_by_gitlab_scheme,
        gitlab_scheme_by_purl_type=gitlab_scheme_by_purl_type,
        logger=logger,
        get_purl_fn=get_purl,
        advisory_url=advisory_url,
    )
