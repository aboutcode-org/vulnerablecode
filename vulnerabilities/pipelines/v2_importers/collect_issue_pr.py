#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from vulnerabilities.pipelines import GitHubCollector
from vulnerabilities.pipelines import GitLabCollector


class CollectKubernetesPRSIssues(GitHubCollector):
    pipeline_id = "collect-kubernetes-prs-issues"
    repo_url = "https://github.com/kubernetes/kubernetes"


class CollectWiresharkPRSIssues(GitLabCollector):
    pipeline_id = "collect-wireshark-prs-issues"
    repo_url = "https://gitlab.com/wireshark/wireshark"
