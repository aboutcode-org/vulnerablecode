#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.improvers import valid_versions
from vulnerabilities.improvers import vulnerability_status
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipelines import add_cvss31_to_CVEs
from vulnerabilities.pipelines import collect_commits
from vulnerabilities.pipelines import compute_package_risk
from vulnerabilities.pipelines import compute_package_version_rank
from vulnerabilities.pipelines import enhance_with_exploitdb
from vulnerabilities.pipelines import enhance_with_kev
from vulnerabilities.pipelines import enhance_with_metasploit
from vulnerabilities.pipelines import flag_ghost_packages
from vulnerabilities.pipelines import populate_vulnerability_summary_pipeline
from vulnerabilities.pipelines import remove_duplicate_advisories

IMPROVERS_REGISTRY = [
    valid_versions.GitHubBasicImprover,
    valid_versions.GitLabBasicImprover,
    valid_versions.NginxBasicImprover,
    valid_versions.ApacheHTTPDImprover,
    valid_versions.DebianBasicImprover,
    valid_versions.NpmImprover,
    valid_versions.ElixirImprover,
    valid_versions.ApacheTomcatImprover,
    valid_versions.ApacheKafkaImprover,
    valid_versions.IstioImprover,
    valid_versions.DebianOvalImprover,
    valid_versions.UbuntuOvalImprover,
    valid_versions.OSSFuzzImprover,
    valid_versions.RubyImprover,
    valid_versions.GithubOSVImprover,
    vulnerability_status.VulnerabilityStatusImprover,
    valid_versions.CurlImprover,
    flag_ghost_packages.FlagGhostPackagePipeline,
    enhance_with_kev.VulnerabilityKevPipeline,
    enhance_with_metasploit.MetasploitImproverPipeline,
    enhance_with_exploitdb.ExploitDBImproverPipeline,
    compute_package_risk.ComputePackageRiskPipeline,
    compute_package_version_rank.ComputeVersionRankPipeline,
    collect_commits.CollectFixCommitsPipeline,
    add_cvss31_to_CVEs.CVEAdvisoryMappingPipeline,
    remove_duplicate_advisories.RemoveDuplicateAdvisoriesPipeline,
    populate_vulnerability_summary_pipeline.PopulateVulnerabilitySummariesPipeline,
]

IMPROVERS_REGISTRY = {
    x.pipeline_id if issubclass(x, VulnerableCodePipeline) else x.qualified_name: x
    for x in IMPROVERS_REGISTRY
}
