#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re

from aboutcode.pipeline import LoopProgress

from vulnerabilities.models import AffectedByPackageRelatedVulnerability
from vulnerabilities.models import CodeFix
from vulnerabilities.pipelines import VulnerableCodePipeline


def is_vcs_url_already_processed(commit_id):
    """
    Check if a VCS URL exists in a CodeFix entry.
    """
    return CodeFix.objects.filter(commits__contains=[commit_id]).exists()


class CollectFixCommitsPipeline(VulnerableCodePipeline):
    """
    Improver pipeline to scout References and create CodeFix entries.
    """

    pipeline_id = "collect_fix_commits"
    license_expression = None

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_fix_commits,)

    def collect_and_store_fix_commits(self):
        affected_by_package_related_vulnerabilities = (
            AffectedByPackageRelatedVulnerability.objects.all().prefetch_related(
                "vulnerability", "vulnerability__references"
            )
        )

        self.log(
            f"Processing {affected_by_package_related_vulnerabilities.count():,d} references to collect fix commits."
        )

        created_fix_count = 0
        progress = LoopProgress(
            total_iterations=affected_by_package_related_vulnerabilities.count(), logger=self.log
        )

        for apv in progress.iter(
            affected_by_package_related_vulnerabilities.paginated(per_page=500)
        ):
            vulnerability = apv.vulnerability
            for reference in vulnerability.references.all():
                if not "/commit/" in reference.url:
                    continue
                if not is_vcs_url(reference.url):
                    continue

                vcs_url = normalize_vcs_url(repo_url=reference.url)

                if not vcs_url:
                    continue

                # Skip if already processed
                if is_vcs_url_already_processed(commit_id=vcs_url):
                    self.log(
                        f"Skipping already processed reference: {reference.url} with VCS URL {vcs_url}"
                    )
                    continue
                # check if vcs_url has commit
                code_fix, created = CodeFix.objects.get_or_create(
                    commits=[vcs_url],
                    affected_package_vulnerability=apv,
                )

                if created:
                    created_fix_count += 1
                    self.log(
                        f"Created CodeFix entry for reference: {reference.url} with VCS URL {vcs_url}"
                    )

        self.log(f"Successfully created {created_fix_count:,d} CodeFix entries.")


PLAIN_URLS = (
    "https://",
    "http://",
)

VCS_URLS = (
    "git://",
    "git+git://",
    "git+https://",
    "git+http://",
    "hg://",
    "hg+http://",
    "hg+https://",
    "svn://",
    "svn+https://",
    "svn+http://",
)


# TODO: This function was borrowed from scancode-toolkit. We need to create a shared library for that.
def normalize_vcs_url(repo_url, vcs_tool=None):
    """
    Return a normalized vcs_url version control URL given some `repo_url` and an
    optional `vcs_tool` hint (such as 'git', 'hg', etc.)

    Return None if repo_url is not recognized as a VCS URL.

    Handles shortcuts for GitHub, GitHub gist, Bitbucket, or GitLab repositories
    and more using the same approach as npm install:

    See https://docs.npmjs.com/files/package.json#repository
    or https://getcomposer.org/doc/05-repositories.md

    This is done here in npm:
    https://github.com/npm/npm/blob/d3c858ce4cfb3aee515bb299eb034fe1b5e44344/node_modules/hosted-git-info/git-host-info.js

    These should be resolved:
        npm/npm
        gist:11081aaa281
        bitbucket:example/repo
        gitlab:another/repo
        expressjs/serve-static
        git://github.com/angular/di.js.git
        git://github.com/hapijs/boom
        git@github.com:balderdashy/waterline-criteria.git
        http://github.com/ariya/esprima.git
        http://github.com/isaacs/nopt
        https://github.com/chaijs/chai
        https://github.com/christkv/kerberos.git
        https://gitlab.com/foo/private.git
        git@gitlab.com:foo/private.git
    """
    if not repo_url or not isinstance(repo_url, str):
        return

    repo_url = repo_url.strip()
    if not repo_url:
        return

    # TODO: If we match http and https, we may should add more check in
    # case if the url is not a repo one. For example, check the domain
    # name in the url...
    if repo_url.startswith(VCS_URLS + PLAIN_URLS):
        return repo_url

    if repo_url.startswith("git@"):
        tool, _, right = repo_url.partition("@")
        if ":" in repo_url:
            host, _, repo = right.partition(":")
        else:
            # git@github.com/Filirom1/npm2aur.git
            host, _, repo = right.partition("/")

        if any(r in host for r in ("bitbucket", "gitlab", "github")):
            scheme = "https"
        else:
            scheme = "git"

        return f"{scheme}://{host}/{repo}"

    # FIXME: where these URL schemes come from??
    if repo_url.startswith(("bitbucket:", "gitlab:", "github:", "gist:")):
        repo = repo_url.split(":")[1]
        hoster_urls = {
            "bitbucket": f"https://bitbucket.org/{repo}",
            "github": f"https://github.com/{repo}",
            "gitlab": f"https://gitlab.com/{repo}",
            "gist": f"https://gist.github.com/{repo}",
        }
        hoster, _, repo = repo_url.partition(":")
        return hoster_urls[hoster] % locals()

    if len(repo_url.split("/")) == 2:
        # implicit github, but that's only on NPM?
        return f"https://github.com/{repo_url}"
    return repo_url


def is_vcs_url(repo_url):
    """
    Check if a given URL or string matches a valid VCS (Version Control System) URL.

    Supports:
    - Standard VCS URL protocols (git, http, https, ssh)
    - Shortcut syntax (e.g., github:user/repo, gitlab:group/repo)
    - GitHub shortcut (e.g., user/repo)

    Args:
        repo_url (str): The repository URL or shortcut to validate.

    Returns:
        bool: True if the string is a valid VCS URL, False otherwise.

    Examples:
        >>> is_vcs_url("git://github.com/angular/di.js.git")
        True
        >>> is_vcs_url("github:user/repo")
        True
        >>> is_vcs_url("user/repo")
        True
        >>> is_vcs_url("https://github.com/user/repo.git")
        True
        >>> is_vcs_url("git@github.com:user/repo.git")
        True
        >>> is_vcs_url("http://github.com/isaacs/nopt")
        True
        >>> is_vcs_url("https://gitlab.com/foo/private.git")
        True
        >>> is_vcs_url("git@gitlab.com:foo/private.git")
        True
        >>> is_vcs_url("bitbucket:example/repo")
        True
        >>> is_vcs_url("gist:11081aaa281")
        True
        >>> is_vcs_url("ftp://example.com/not-a-repo")
        False
        >>> is_vcs_url("random-string")
        False
        >>> is_vcs_url("https://example.com/not-a-repo")
        False
    """
    if not repo_url or not isinstance(repo_url, str):
        return False

    repo_url = repo_url.strip()
    if not repo_url:
        return False

    # Define valid VCS domains
    vcs_domains = r"(github\.com|gitlab\.com|bitbucket\.org|gist\.github\.com)"

    # 1. Match URLs with standard protocols pointing to VCS domains
    if re.match(rf"^(git|ssh|http|https)://{vcs_domains}/[\w\-.]+/[\w\-.]+", repo_url):
        return True

    # 2. Match SSH URLs (e.g., git@github.com:user/repo.git)
    if re.match(rf"^git@{vcs_domains}:[\w\-.]+/[\w\-.]+(\.git)?$", repo_url):
        return True

    # 3. Match shortcut syntax (e.g., github:user/repo)
    if re.match(r"^(github|gitlab|bitbucket|gist):[\w\-./]+$", repo_url):
        return True

    # 4. Match implicit GitHub shortcut (e.g., user/repo)
    if re.match(r"^[\w\-]+/[\w\-]+$", repo_url):
        return True

    return False
