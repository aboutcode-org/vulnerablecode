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
from vulnerabilities.importers import apache_kafka
from vulnerabilities.importers import apache_tomcat
from vulnerabilities.importers import archlinux
from vulnerabilities.importers import debian
from vulnerabilities.importers import debian_oval
from vulnerabilities.importers import elixir_security
from vulnerabilities.importers import fireeye
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
from vulnerabilities.importers import project_kb_msr2019
from vulnerabilities.importers import pypa
from vulnerabilities.importers import pysec
from vulnerabilities.importers import redhat
from vulnerabilities.importers import retiredotnet
from vulnerabilities.importers import suse_scores
from vulnerabilities.importers import ubuntu
from vulnerabilities.importers import ubuntu_usn
from vulnerabilities.importers import xen

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
    project_kb_msr2019.ProjectKBMSRImporter,
    suse_scores.SUSESeverityScoreImporter,
    elixir_security.ElixirSecurityImporter,
    apache_tomcat.ApacheTomcatImporter,
    xen.XenImporter,
    ubuntu_usn.UbuntuUSNImporter,
    fireeye.FireyeImporter,
    apache_kafka.ApacheKafkaImporter,
]

IMPORTERS_REGISTRY = {x.qualified_name: x for x in IMPORTERS_REGISTRY}
