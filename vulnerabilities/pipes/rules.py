from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.pipelines import VulnerableCodePipeline


class BaseRuleImproverPipeline(VulnerableCodePipeline):
    """
    Base pipeline for fetching, parsing, and storing detection rules (Sigma, Suricata, etc.).
    Subclasses must define `rglob_patterns` and implement `process_rule_file`.
    """

    repo_url = None
    rglob_patterns = []

    @classmethod
    def steps(cls):
        return (
            cls.clone_repo,
            cls.collect_and_store_rules,
            cls.clean_downloads,
        )

    def clone_repo(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(f"git+{self.repo_url}")

    def collect_and_store_rules(self):
        raise NotImplementedError

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository: {self.vcs_response.dest_dir}")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
