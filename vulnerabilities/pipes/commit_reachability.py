#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.models import PackageCommitPatch


def get_branch_reachability(repo, commit_hashes, *, all_branches_fetched=False):
    """Return reachability for commits against a complete snapshot of branch heads.

    The caller must establish that all repository branches were fetched. Shallow
    and partial clones cannot prove absence and yield unknown results. Tags,
    detached HEADs, and pull request refs do not count as repository branches.
    Git errors propagate so the caller can report unknown and retry later.
    """
    status = PackageCommitPatch.BranchReachability
    results = dict.fromkeys(commit_hashes, status.UNKNOWN)
    if not all_branches_fetched or repo.git.rev_parse("--is-shallow-repository") == "true":
        return results

    with repo.config_reader() as config:
        if config.has_option("extensions", "partialclone"):
            return results
        for section in config.sections():
            if section.startswith('remote "') and config.get_value(section, "promisor", False):
                return results

    # Traverse branch histories once, without fetching objects mentioned only in
    # advisories. A missing object is unreachable only after this walk succeeds.
    reachable = set(repo.git.rev_list("--branches", "--missing=error").splitlines())
    for commit_hash in results:
        normalized = commit_hash.lower()
        if len(normalized) in (40, 64):
            results[commit_hash] = (
                status.REACHABLE if normalized in reachable else status.UNREACHABLE
            )
        else:
            matches = sum(commit.startswith(normalized) for commit in reachable)
            if matches == 1:
                results[commit_hash] = status.REACHABLE
            elif matches == 0:
                results[commit_hash] = status.UNREACHABLE
            # An ambiguous abbreviated hash remains unknown.
    return results
