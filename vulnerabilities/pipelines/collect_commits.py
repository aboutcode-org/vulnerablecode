#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from aboutcode.pipeline import LoopProgress
from packageurl.contrib.url2purl import url2purl

from vulnerabilities.models import CodeFix
from vulnerabilities.models import Package
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.pipelines import VulnerableCodePipeline


def extract_commit_id(url):
    """
    Extract a commit ID from a URL, if available.
    Supports different URL structures for commit references.

    >>> extract_commit_id("https://github.com/hedgedoc/hedgedoc/commit/c1789474020a6d668d616464cb2da5e90e123f65")
    'c1789474020a6d668d616464cb2da5e90e123f65'
    """
    if "/commit/" in url:
        parts = url.split("/")
        if len(parts) > 1 and parts[-2] == "commit":
            return parts[-1]
    return None


def is_reference_already_processed(reference_url, commit_id):
    """
    Check if a reference and commit ID pair already exists in a CodeFix entry.
    """
    return CodeFix.objects.filter(
        references__contains=[reference_url], commits__contains=[commit_id]
    ).exists()


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
        references = VulnerabilityReference.objects.prefetch_related("vulnerabilities").distinct()

        self.log(f"Processing {references.count():,d} references to collect fix commits.")

        created_fix_count = 0
        progress = LoopProgress(total_iterations=references.count(), logger=self.log)
        for reference in progress.iter(references.paginated(per_page=500)):
            for vulnerability in reference.vulnerabilities.all():
                vcs_url = normalize_vcs_url(reference.url)
                commit_id = extract_commit_id(reference.url)

                if not commit_id or not vcs_url:
                    continue

                # Skip if already processed
                if is_reference_already_processed(reference.url, commit_id):
                    self.log(
                        f"Skipping already processed reference: {reference.url} with commit {commit_id}"
                    )
                    continue
                purl = url2purl(vcs_url)
                if not purl:
                    self.log(f"Could not create purl from url: {vcs_url}")
                    continue
                package = self.get_or_create_package(purl)
                codefix = self.create_codefix_entry(
                    vulnerability=vulnerability,
                    package=package,
                    commit_id=commit_id,
                    reference=reference.url,
                )
                if codefix:
                    created_fix_count += 1

        self.log(f"Successfully created {created_fix_count:,d} CodeFix entries.")

    def get_or_create_package(self, purl):
        """
        Get or create a Package object from a Package URL.
        """
        try:
            package, _ = Package.objects.get_or_create_from_purl(purl)
            return package
        except Exception as e:
            self.log(f"Error creating package from purl {purl}: {e}")
            return None

    def create_codefix_entry(self, vulnerability, package, commit_id, reference):
        """
        Create a CodeFix entry associated with the given vulnerability and package.
        """
        try:
            codefix, created = CodeFix.objects.get_or_create(
                base_version=package,
                defaults={
                    "commits": [commit_id],
                    "references": [reference],
                },
            )
            if created:
                codefix.vulnerabilities.add(vulnerability)
                codefix.save()
            return codefix
        except Exception as e:
            self.log(f"Error creating CodeFix entry: {e}")
            return


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


def normalize_vcs_url(repo_url, vcs_tool=None):
    """
    Return a normalized vcs_url version control URL given some `repo_url` and an
    optional `vcs_tool` hint (such as 'git', 'hg', etc.

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
