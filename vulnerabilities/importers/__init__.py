#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.importers import alpine_linux
from vulnerabilities.importers import apache_httpd
from vulnerabilities.importers import archlinux
from vulnerabilities.importers import debian
from vulnerabilities.importers import debian_oval
from vulnerabilities.importers import gentoo
from vulnerabilities.importers import github
from vulnerabilities.importers import gitlab
from vulnerabilities.importers import istio
from vulnerabilities.importers import mozilla
from vulnerabilities.importers import nginx
from vulnerabilities.importers import npm
from vulnerabilities.importers import nvd
from vulnerabilities.importers import openssl
from vulnerabilities.importers import postgresql
from vulnerabilities.importers import pypa
from vulnerabilities.importers import pysec
from vulnerabilities.importers import redhat
from vulnerabilities.importers import retiredotnet
from vulnerabilities.importers import ubuntu

IMPORTERS_REGISTRY = [
    nginx.NginxImporter,
    alpine_linux.AlpineImporter,
    github.GitHubAPIImporter,
    nvd.NVDImporter,
    openssl.OpensslImporter,
    redhat.RedhatImporter,
    pysec.PyPIImporter,
    debian.DebianImporter,
    gitlab.GitLabAPIImporter,
    postgresql.PostgreSQLImporter,
    pypa.PyPaImporter,
    archlinux.ArchlinuxImporter,
    ubuntu.UbuntuImporter,
    debian_oval.DebianOvalImporter,
    npm.NpmImporter,
    retiredotnet.RetireDotnetImporter,
    apache_httpd.ApacheHTTPDImporter,
    mozilla.MozillaImporter,
    gentoo.GentooImporter,
    istio.IstioImporter,
]

IMPORTERS_REGISTRY = {x.qualified_name: x for x in IMPORTERS_REGISTRY}
