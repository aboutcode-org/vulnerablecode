#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities import importers
from vulnerabilities.improvers import default
from vulnerabilities.improvers import oval

IMPROVERS_REGISTRY = [
    default.DefaultImprover,
    importers.nginx.NginxBasicImprover,
    importers.github.GitHubBasicImprover,
    importers.debian.DebianBasicImprover,
    importers.gitlab.GitLabBasicImprover,
    oval.DebianOvalBasicImprover,
    oval.UbuntuOvalBasicImprover,
]

IMPROVERS_REGISTRY = {x.qualified_name: x for x in IMPROVERS_REGISTRY}
