#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

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
from vulnerabilities.pipelines import alpine_linux_importer
from vulnerabilities.pipelines import github_importer
from vulnerabilities.pipelines import gitlab_importer
from vulnerabilities.pipelines import nginx_importer
from vulnerabilities.pipelines import npm_importer
from vulnerabilities.pipelines import nvd_importer
from vulnerabilities.pipelines import pypa_importer
from vulnerabilities.pipelines import pysec_importer
from vulnerabilities.pipelines.v2_importers import apache_httpd_importer as apache_httpd_v2
from vulnerabilities.pipelines.v2_importers import archlinux_importer as archlinux_importer_v2
from vulnerabilities.pipelines.v2_importers import curl_importer as curl_importer_v2
from vulnerabilities.pipelines.v2_importers import (
    elixir_security_importer as elixir_security_importer_v2,
)
from vulnerabilities.pipelines.v2_importers import github_osv_importer as github_osv_importer_v2
from vulnerabilities.pipelines.v2_importers import gitlab_importer as gitlab_importer_v2
from vulnerabilities.pipelines.v2_importers import istio_importer as istio_importer_v2
from vulnerabilities.pipelines.v2_importers import mozilla_importer as mozilla_importer_v2
from vulnerabilities.pipelines.v2_importers import npm_importer as npm_importer_v2
from vulnerabilities.pipelines.v2_importers import nvd_importer as nvd_importer_v2
from vulnerabilities.pipelines.v2_importers import oss_fuzz as oss_fuzz_v2
from vulnerabilities.pipelines.v2_importers import postgresql_importer as postgresql_importer_v2
from vulnerabilities.pipelines.v2_importers import pypa_importer as pypa_importer_v2
from vulnerabilities.pipelines.v2_importers import pysec_importer as pysec_importer_v2
from vulnerabilities.pipelines.v2_importers import vulnrichment_importer as vulnrichment_importer_v2
from vulnerabilities.pipelines.v2_importers import xen_importer as xen_importer_v2
from vulnerabilities.utils import create_registry

IMPORTERS_REGISTRY = create_registry(
    [
        archlinux_importer_v2.ArchLinuxImporterPipeline,
        nvd_importer_v2.NVDImporterPipeline,
        elixir_security_importer_v2.ElixirSecurityImporterPipeline,
        npm_importer_v2.NpmImporterPipeline,
        vulnrichment_importer_v2.VulnrichImporterPipeline,
        apache_httpd_v2.ApacheHTTPDImporterPipeline,
        pypa_importer_v2.PyPaImporterPipeline,
        gitlab_importer_v2.GitLabImporterPipeline,
        pysec_importer_v2.PyPIImporterPipeline,
        xen_importer_v2.XenImporterPipeline,
        curl_importer_v2.CurlImporterPipeline,
        oss_fuzz_v2.OSSFuzzImporterPipeline,
        istio_importer_v2.IstioImporterPipeline,
        postgresql_importer_v2.PostgreSQLImporterPipeline,
        mozilla_importer_v2.MozillaImporterPipeline,
        github_osv_importer_v2.GithubOSVImporterPipeline,
        nvd_importer.NVDImporterPipeline,
        github_importer.GitHubAPIImporterPipeline,
        gitlab_importer.GitLabImporterPipeline,
        github_osv.GithubOSVImporter,
        pypa_importer.PyPaImporterPipeline,
        npm_importer.NpmImporterPipeline,
        nginx_importer.NginxImporterPipeline,
        pysec_importer.PyPIImporterPipeline,
        apache_tomcat.ApacheTomcatImporter,
        postgresql.PostgreSQLImporter,
        debian.DebianImporter,
        curl.CurlImporter,
        epss.EPSSImporter,
        vulnrichment.VulnrichImporter,
        alpine_linux_importer.AlpineLinuxImporterPipeline,
        ruby.RubyImporter,
        apache_kafka.ApacheKafkaImporter,
        openssl.OpensslImporter,
        redhat.RedhatImporter,
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
        xen.XenImporter,
        ubuntu_usn.UbuntuUSNImporter,
        fireeye.FireyeImporter,
        oss_fuzz.OSSFuzzImporter,
    ]
)
