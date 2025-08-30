#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import bisect
import re
from collections import defaultdict
from typing import List
from typing import Optional
from typing import Tuple

from git import Commit
from git import Repo

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import CodeFixV2
from vulnerabilities.pipelines import VulnerableCodePipeline


class CollectRepoFixCommitPipeline(VulnerableCodePipeline):
    """
    Pipeline to collect fix commits from any git repository.
    """

    pipeline_id = "repo_fix_commit_pipeline"
    repositories_url = "git+https://github.com/the-tcpdump-group/tcpdump"

    @classmethod
    def steps(cls):
        return (
            cls.collect_fix_commits,
            cls.store_fix_commits,
        )

    def classify_commit_type(self, commit) -> str:
        num_parents = len(commit.parents)
        if num_parents == 0:
            return "root"
        elif num_parents == 1:
            return "normal"
        else:
            return "merge"

    def detect_fix_commit(self, commit) -> str:
        """
        Detect whether a commit is a bug-fix or vulnerability-fix commit.
        Returns: "vulnerability_fix" or "other"
        """
        msg = commit.message.lower()
        security_patterns = [
            # CVE identifiers
            r"\bcve-[0-9]{4}-[0-9]{4,19}\b",
        ]
        if any(re.search(p, msg) for p in security_patterns):
            return "vulnerability_fix"
        return "other"

    def extract_cves(self, text: str) -> List[str]:
        if not text:
            return []
        cves = re.findall(r"cve-[0-9]{4}-[0-9]{4,19}", text, flags=re.IGNORECASE)
        return list({cve.upper() for cve in cves})

    def get_previous_releases(
        self,
        release_tags_sorted: List[Tuple[str, int]],
        dates: List[int],
        commit_date: int,
    ) -> List[str]:
        index = bisect.bisect_left(dates, commit_date)
        return [tag for tag, _ in release_tags_sorted[:index]]

    def get_current_or_next_release(
        self,
        release_tags_sorted: List[Tuple[str, int]],
        dates: List[int],
        commit_date: int,
    ) -> Optional[str]:
        index = bisect.bisect_left(dates, commit_date)

        if index < len(dates) and dates[index] == commit_date:
            return release_tags_sorted[index][0]

        if index < len(dates):
            return release_tags_sorted[index][0]

        return None

    def get_current_release(
        self, repo: Repo, commit: Commit, prev_release_by_date: Optional[str]
    ) -> str:
        try:
            return repo.git.describe("--tags", "--exact-match", commit.hexsha)
        except Exception:
            pass

        try:
            return repo.git.describe("--tags", "--abbrev=0", "--first-parent", commit.hexsha)
        except Exception:
            pass

        if prev_release_by_date:
            return prev_release_by_date

        return "NO_TAGS_AVAILABLE"

    def collect_fix_commits(self):
        self.log("Processing git repository fix commits.")
        repo_url = "https://github.com/the-tcpdump-group/tcpdump"
        repo_path = "/home/ziad-hany/PycharmProjects/tcpdump"

        repo = Repo(repo_path)
        cve_list = defaultdict(set)

        # Precompute release tags
        release_tags = []
        for tag in repo.tags:
            try:
                release_tags.append((tag.name, tag.commit.committed_date))
            except Exception:
                continue

        release_tags_sorted = sorted(release_tags, key=lambda x: x[1])
        dates_array = [date for _, date in release_tags_sorted]

        for commit in repo.iter_commits("--all"):
            commit_type = self.classify_commit_type(commit)
            fix_type = self.detect_fix_commit(commit)

            if fix_type == "vulnerability_fix" and commit_type in ["normal", "merge"]:
                prev_release_list = self.get_previous_releases(
                    release_tags_sorted, dates_array, commit.committed_date
                )
                prev_release_by_date = prev_release_list[-1] if prev_release_list else None

                curr_release = self.get_current_release(repo, commit, prev_release_by_date)
                commit_info = {
                    "hash": commit.hexsha,
                    "url": repo_url + "/commit/" + commit.hexsha,
                    "message": commit.message.strip(),
                    "curr_release": curr_release,
                    "prev_release": prev_release_list,
                    "fix_type": fix_type,
                }

                for cve_id in self.extract_cves(commit.message.strip()):
                    commit_url = f"{repo_url}/commit/{commit.hexsha}"
                    cve_list[cve_id].add(commit_url)

        # Save results into pipeline state
        self.fix_commits = {cve: list(commits) for cve, commits in cve_list.items()}
        self.log(f"Found {len(self.fix_commits)} unique CVEs with fix commits.")

    def store_fix_commits(self):
        if not hasattr(self, "fix_commits"):
            self.log("No fix commits collected. Run collect_fix_commits() first.")
            return

        created_fix_count = 0

        # FIXME
        for vulnerability_id, commit_urls in self.fix_commits.items():
            advisories = AdvisoryV2.objects.filter(advisory_id__iendswith=vulnerability_id)

            if not advisories.exists():
                self.log(f"No advisories found for vulnerability_id: {vulnerability_id}")
                continue

            for adv in advisories:
                for impact in adv.impacted_packages.all():
                    for package in impact.affecting_packages.all():
                        for vcs_url in commit_urls:
                            code_fix, created = CodeFixV2.objects.get_or_create(
                                commits=[vcs_url],
                                advisory=adv,
                                affected_package=package,
                            )
                            if created:
                                created_fix_count += 1

        self.log(f"Stored {created_fix_count} new CodeFixV2 entries.")
