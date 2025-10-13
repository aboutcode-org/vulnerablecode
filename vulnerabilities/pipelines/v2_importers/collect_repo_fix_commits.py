import os
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict

from git import Repo

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2

SECURITY_PATTERNS = [
    r"\bCVE-\d{4}-\d{4,19}\b",
    r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b",
    r"\bPYSEC-\d{4}-\d{1,6}\b",
    r"\bXSA-\d{1,4}\b",
]


class CollectRepoFixCommitPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline to collect fix commits from any git repository.
    """

    pipeline_id = "repo_fix_commit"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        """Clone the repository."""
        self.repo_url = "https://github.com/torvalds/linux"
        repo_path = tempfile.mkdtemp()
        cmd = [
            "git",
            "clone",
            "--bare",
            "--filter=blob:none",
            "--no-checkout",
            self.repo_url,
            repo_path,
        ]
        subprocess.run(cmd, check=True)
        self.repo = Repo(repo_path)

    def advisories_count(self) -> int:
        return int(self.repo.git.rev_list("--count", "HEAD"))

    def classify_commit_type(self, commit) -> list[str]:
        """
        Extract vulnerability identifiers from a commit message.
        Returns a list of matched vulnerability IDs (normalized to uppercase).
        """
        matches = []
        for pattern in SECURITY_PATTERNS:
            found = re.findall(pattern, commit.message, flags=re.IGNORECASE)
            matches.extend(found)
        return matches

    def collect_fix_commits(self):
        """
        Iterate through repository commits and group them by vulnerability identifiers.
        return a list with (vuln_id, [(commit_id, commit_message)]).
        """
        self.log("Processing git repository fix commits (grouped by vulnerability IDs).")

        grouped_commits = defaultdict(list)
        for commit in self.repo.iter_commits("--all"):
            matched_ids = self.classify_commit_type(commit)
            if not matched_ids:
                continue

            commit_id = commit.hexsha
            commit_message = commit.message.strip()

            for vuln_id in matched_ids:
                grouped_commits[vuln_id].append((commit_id, commit_message))

        self.log(f"Found {len(grouped_commits)} vulnerabilities with related commits.")
        self.log("Finished processing all commits.")
        return grouped_commits

    def collect_advisories(self):
        """
        Generate AdvisoryData objects for each vulnerability ID grouped with its related commits.
        """
        self.log("Generating AdvisoryData objects from grouped commits.")
        grouped_commits = self.collect_fix_commits()
        for vuln_id, commits in grouped_commits.items():
            references = [ReferenceV2(url=f"{self.repo_url}/commit/{cid}") for cid, _ in commits]

            summary_lines = [f"- {cid}: {msg}" for cid, msg in commits]
            summary = f"Commits fixing {vuln_id}:\n" + "\n".join(summary_lines)
            yield AdvisoryData(
                advisory_id=vuln_id,
                aliases=[vuln_id],
                summary=summary,
                references_v2=references,
                url=self.repo_url,
            )

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        self.log("Cleaning up local repository resources.")
        if os.path.isdir(self.repo.working_tree_dir):
            shutil.rmtree(path=self.repo.working_tree_dir)

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
