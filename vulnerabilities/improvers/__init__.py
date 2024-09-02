#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.improvers import valid_versions
from vulnerabilities.improvers import vulnerability_kev
from vulnerabilities.improvers import vulnerability_status
from vulnerabilities.pipelines import flag_ghost_packages

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
    vulnerability_kev.VulnerabilityKevImprover,
    flag_ghost_packages.FlagGhostPackagePipeline,
]

IMPROVERS_REGISTRY = {x.qualified_name: x for x in IMPROVERS_REGISTRY}
