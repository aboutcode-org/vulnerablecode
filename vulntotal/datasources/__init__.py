#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulntotal.datasources import deps
from vulntotal.datasources import github
from vulntotal.datasources import gitlab
from vulntotal.datasources import oss_index
from vulntotal.datasources import osv
from vulntotal.datasources import snyk
from vulntotal.datasources import vulnerablecode
from vulntotal.validator import DataSource

DATASOURCE_REGISTRY = {
    "deps": deps.DepsDataSource,
    "github": github.GithubDataSource,
    "gitlab": gitlab.GitlabDataSource,
    "oss_index": oss_index.OSSDataSource,
    "osv": osv.OSVDataSource,
    "snyk": snyk.SnykDataSource,
    "vulnerablecode": vulnerablecode.VulnerableCodeDataSource,
}
