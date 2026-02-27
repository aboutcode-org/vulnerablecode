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
from vulnerabilities.pipelines import add_cvss31_to_CVEs
from vulnerabilities.pipelines import compute_advisory_todo
from vulnerabilities.pipelines import compute_package_risk
from vulnerabilities.pipelines import compute_package_version_rank
from vulnerabilities.pipelines import enhance_with_exploitdb
from vulnerabilities.pipelines import enhance_with_kev
from vulnerabilities.pipelines import enhance_with_metasploit
from vulnerabilities.pipelines import flag_ghost_packages
from vulnerabilities.pipelines import populate_vulnerability_summary_pipeline
from vulnerabilities.pipelines import remove_duplicate_advisories
from vulnerabilities.pipelines.v2_improvers import collect_ssvc_trees
from vulnerabilities.pipelines.v2_improvers import compute_advisory_todo as compute_advisory_todo_v2
from vulnerabilities.pipelines.v2_improvers import compute_package_risk as compute_package_risk_v2
from vulnerabilities.pipelines.v2_improvers import (
    computer_package_version_rank as compute_version_rank_v2,
)
from vulnerabilities.pipelines.v2_improvers import enhance_with_exploitdb as exploitdb_v2
from vulnerabilities.pipelines.v2_improvers import enhance_with_kev as enhance_with_kev_v2
from vulnerabilities.pipelines.v2_improvers import (
    enhance_with_metasploit as enhance_with_metasploit_v2,
)
from vulnerabilities.pipelines.v2_improvers import flag_ghost_packages as flag_ghost_packages_v2
from vulnerabilities.pipelines.v2_improvers import relate_severities
from vulnerabilities.pipelines.v2_improvers import unfurl_version_range as unfurl_version_range_v2
from vulnerabilities.pipelines.v2_improvers import fetch_patch_url as fetch_patch_url_v2
from vulnerabilities.utils import create_registry

IMPROVERS_REGISTRY = create_registry(
    [
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
        add_cvss31_to_CVEs.CVEAdvisoryMappingPipeline,
        remove_duplicate_advisories.RemoveDuplicateAdvisoriesPipeline,
        populate_vulnerability_summary_pipeline.PopulateVulnerabilitySummariesPipeline,
        exploitdb_v2.ExploitDBImproverPipeline,
        enhance_with_kev_v2.VulnerabilityKevPipeline,
        flag_ghost_packages_v2.FlagGhostPackagePipeline,
        enhance_with_metasploit_v2.MetasploitImproverPipeline,
        compute_package_risk_v2.ComputePackageRiskPipeline,
        compute_version_rank_v2.ComputeVersionRankPipeline,
        compute_advisory_todo_v2.ComputeToDo,
        unfurl_version_range_v2.UnfurlVersionRangePipeline,
        fetch_patch_url_v2.FetchPatchURLImproverPipeline,
        compute_advisory_todo.ComputeToDo,
        collect_ssvc_trees.CollectSSVCPipeline,
        relate_severities.RelateSeveritiesPipeline,
    ]
)
