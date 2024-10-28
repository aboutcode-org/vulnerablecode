#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.importers import alpine_linux
from vulnerabilities.importers import apache_httpd
from vulnerabilities.importers import apache_kafka
from vulnerabilities.importers import apache_tomcat
from vulnerabilities.importers import archlinux
from vulnerabilities.importers import curl
from vulnerabilities.importers import debian
from vulnerabilities.importers import debian_oval
from vulnerabilities.importers import elixir_security
from vulnerabilities.importers import epss
from vulnerabilities.importers import fireeye
from vulnerabilities.importers import gentoo
from vulnerabilities.importers import github_osv
from vulnerabilities.importers import istio
from vulnerabilities.importers import mozilla
from vulnerabilities.importers import openssl
from vulnerabilities.importers import oss_fuzz
from vulnerabilities.importers import postgresql
from vulnerabilities.importers import project_kb_msr2019
from vulnerabilities.importers import redhat
from vulnerabilities.importers import retiredotnet
from vulnerabilities.importers import ruby
from vulnerabilities.importers import suse_scores
from vulnerabilities.importers import ubuntu
from vulnerabilities.importers import ubuntu_usn
from vulnerabilities.importers import vulnrichment
from vulnerabilities.importers import xen
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipeline
from vulnerabilities.pipelines import github_importer
from vulnerabilities.pipelines import gitlab_importer
from vulnerabilities.pipelines import nginx_importer
from vulnerabilities.pipelines import npm_importer
from vulnerabilities.pipelines import nvd_importer
from vulnerabilities.pipelines import pypa_importer
from vulnerabilities.pipelines import pysec_importer

IMPORTERS_REGISTRY = [
    alpine_linux.AlpineImporter,
    openssl.OpensslImporter,
    redhat.RedhatImporter,
    debian.DebianImporter,
    postgresql.PostgreSQLImporter,
    archlinux.ArchlinuxImporter,
    ubuntu.UbuntuImporter,
    debian_oval.DebianOvalImporter,
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
    oss_fuzz.OSSFuzzImporter,
    ruby.RubyImporter,
    github_osv.GithubOSVImporter,
    curl.CurlImporter,
    epss.EPSSImporter,
    vulnrichment.VulnrichImporter,
    pypa_importer.PyPaImporterPipeline,
    npm_importer.NpmImporterPipeline,
    nginx_importer.NginxImporterPipeline,
    gitlab_importer.GitLabImporterPipeline,
    github_importer.GitHubAPIImporterPipeline,
    nvd_importer.NVDImporterPipeline,
    pysec_importer.PyPIImporterPipeline,
]

IMPORTERS_REGISTRY = {
    x.pipeline_id if issubclass(x, VulnerableCodeBaseImporterPipeline) else x.qualified_name: x
    for x in IMPORTERS_REGISTRY
}
