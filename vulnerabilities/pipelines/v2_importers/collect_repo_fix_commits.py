import re
import shutil
import tempfile
from collections import defaultdict

from git import Repo

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import PackageCommitPatchData
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

    pipeline_id = "collect_fix_commit"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        """Clone the repository."""
        self.repo_url = self.inputs["repo_url"]
        if not self.repo_url:
            raise ValueError("Repo is required for CollectRepoFixCommitPipeline")

        self.purl = self.inputs["purl"]
        self.repo = Repo.clone_from(
            url=self.repo_url,
            to_path=tempfile.mkdtemp(),
            bare=True,
            no_checkout=True,
            multi_options=["--filter=blob:none"],
        )

    def advisories_count(self) -> int:
        return 0

    def extract_vulnerability_id(self, commit) -> list[str]:
        """
        Extract vulnerability id from a commit message.
        Returns a list of matched vulnerability IDs
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
            matched_ids = self.extract_vulnerability_id(commit)
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
        for vuln_id, commits_data in grouped_commits.items():
            if not commits_data or not vuln_id:
                continue

            summary_lines = []
            for c_hash, msg in commits_data:
                summary_lines.append(f"{c_hash}: {msg}")
            summary = f"Commits fixing {vuln_id}:\n" + "\n".join(summary_lines)

            commit_hash_set = {commit_hash for commit_hash, _ in commits_data}
            affected_packages = [
                AffectedPackageV2(
                    package=self.purl,
                    fixed_by_commit_patches=[
                        PackageCommitPatchData(vcs_url=self.repo_url, commit_hash=commit_hash)
                        for commit_hash in commit_hash_set
                    ],
                )
            ]

            yield AdvisoryData(
                advisory_id=vuln_id,
                summary=summary,
                affected_packages=affected_packages,
                url=self.repo_url,
            )

    def clean_downloads(self):
        """Cleanup any temporary repository data."""
        self.log("Cleaning up local repository resources.")
        if hasattr(self, "repo") and self.repo.working_dir:
            shutil.rmtree(path=self.repo.working_dir)

    def on_failure(self):
        """Ensure cleanup is always performed on failure."""
        self.clean_downloads()
