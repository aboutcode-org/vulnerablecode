#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.pipelines.v2_improvers import archive_urls
from vulnerabilities.pipelines.v2_improvers import collect_ssvc_trees
from vulnerabilities.pipelines.v2_improvers import compute_advisory_todo as compute_advisory_todo_v2
from vulnerabilities.pipelines.v2_improvers import compute_package_risk as compute_package_risk_v2
from vulnerabilities.pipelines.v2_improvers import enhance_with_exploitdb as exploitdb_v2
from vulnerabilities.pipelines.v2_improvers import enhance_with_github_poc
from vulnerabilities.pipelines.v2_improvers import enhance_with_kev as enhance_with_kev_v2
from vulnerabilities.pipelines.v2_improvers import (
    enhance_with_metasploit as enhance_with_metasploit_v2,
)
from vulnerabilities.pipelines.v2_improvers import flag_ghost_packages as flag_ghost_packages_v2
from vulnerabilities.pipelines.v2_improvers import (
    group_advisories_for_packages as group_advisories_for_packages_v2,
)
from vulnerabilities.pipelines.v2_improvers import mark_unfurl_version_range
from vulnerabilities.pipelines.v2_improvers import reference_collect_commits
from vulnerabilities.pipelines.v2_improvers import relate_severities
from vulnerabilities.pipelines.v2_improvers import unfurl_version_range as unfurl_version_range_v2
from vulnerabilities.utils import create_registry

IMPROVERS_REGISTRY = create_registry(
    [
        exploitdb_v2.ExploitDBImproverPipeline,
        enhance_with_kev_v2.VulnerabilityKevPipeline,
        flag_ghost_packages_v2.FlagGhostPackagePipeline,
        enhance_with_metasploit_v2.MetasploitImproverPipeline,
        compute_package_risk_v2.ComputePackageRiskPipeline,
        unfurl_version_range_v2.UnfurlVersionRangePipeline,
        collect_ssvc_trees.CollectSSVCPipeline,
        relate_severities.RelateSeveritiesPipeline,
        archive_urls.ArchiveImproverPipeline,
        compute_advisory_todo_v2.ComputeToDo,
        reference_collect_commits.CollectReferencesFixCommitsPipeline,
        enhance_with_github_poc.GithubPocsImproverPipeline,
        mark_unfurl_version_range.MarkUnfurlVersionRangePipeline,
        group_advisories_for_packages_v2.GroupAdvisoriesForPackages,
    ]
)
