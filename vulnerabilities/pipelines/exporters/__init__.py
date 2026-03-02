# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.pipelines.exporters import federate_vulnerabilities
from vulnerabilities.utils import create_registry

EXPORTERS_REGISTRY = create_registry(
    [
        federate_vulnerabilities.FederatePackageVulnerabilities,
    ]
)
