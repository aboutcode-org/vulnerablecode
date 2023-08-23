#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.improvers import importer_specific_improver
from vulnerabilities.improvers import valid_versions

IMPROVERS_REGISTRY = [
    importer_specific_improver.NVDImprover,
    importer_specific_improver.DebianImprover,
    importer_specific_improver.DebianOvalImprover,
    importer_specific_improver.AlpineLinuxImprover,
    importer_specific_improver.ApacheHTTPDImprover,
    importer_specific_improver.ApacheKafkaImprover,
    importer_specific_improver.ApacheTomcatImprover,
    importer_specific_improver.ArchLinuxImprover,
    importer_specific_improver.ElixirSecurityImprover,
    importer_specific_improver.FireEyeImprover,
    importer_specific_improver.GentooImprover,
    importer_specific_improver.GitHubAPIImprover,
    importer_specific_improver.GitLabAPIImprover,
    importer_specific_improver.IstioImprover,
    importer_specific_improver.MozillaImprover,
    importer_specific_improver.NginxImprover,
    importer_specific_improver.NpmImprover,
    importer_specific_improver.OpensslImprover,
    importer_specific_improver.PostgreSQLImprover,
    importer_specific_improver.ProjectKBMSRImprover,
    importer_specific_improver.PyPaImprover,
    importer_specific_improver.PyPIImprover,
    importer_specific_improver.RedhatImprover,
    importer_specific_improver.RetireDotnetImprover,
    importer_specific_improver.SUSESeverityScoreImprover,
    importer_specific_improver.UbuntuImprover,
    importer_specific_improver.UbuntuUSNImprover,
    importer_specific_improver.XenImprover,
    valid_versions.NginxBasicImprover,
    valid_versions.ApacheHTTPDImprover,
    valid_versions.DebianBasicImprover,
    valid_versions.GitHubBasicImprover,
    valid_versions.GitLabBasicImprover,
    valid_versions.NpmImprover,
    valid_versions.ElixirImprover,
    valid_versions.ApacheTomcatImprover,
    valid_versions.ApacheKafkaImprover,
    valid_versions.IstioImprover,
    valid_versions.DebianOvalImprover,
    valid_versions.UbuntuOvalImprover,
]

IMPROVERS_REGISTRY = {x.qualified_name: x for x in IMPROVERS_REGISTRY}
