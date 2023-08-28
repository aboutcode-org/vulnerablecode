#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.importers.alpine_linux import AlpineImporter
from vulnerabilities.importers.apache_httpd import ApacheHTTPDImporter
from vulnerabilities.importers.apache_kafka import ApacheKafkaImporter
from vulnerabilities.importers.apache_tomcat import ApacheTomcatImporter
from vulnerabilities.importers.archlinux import ArchlinuxImporter
from vulnerabilities.importers.debian import DebianImporter
from vulnerabilities.importers.debian_oval import DebianOvalImporter
from vulnerabilities.importers.elixir_security import ElixirSecurityImporter
from vulnerabilities.importers.fireeye import FireyeImporter
from vulnerabilities.importers.gentoo import GentooImporter
from vulnerabilities.importers.github import GitHubAPIImporter
from vulnerabilities.importers.gitlab import GitLabAPIImporter
from vulnerabilities.importers.istio import IstioImporter
from vulnerabilities.importers.mozilla import MozillaImporter
from vulnerabilities.importers.nginx import NginxImporter
from vulnerabilities.importers.npm import NpmImporter
from vulnerabilities.importers.nvd import NVDImporter
from vulnerabilities.importers.openssl import OpensslImporter
from vulnerabilities.importers.postgresql import PostgreSQLImporter
from vulnerabilities.importers.project_kb_msr2019 import ProjectKBMSRImporter
from vulnerabilities.importers.pypa import PyPaImporter
from vulnerabilities.importers.pysec import PyPIImporter
from vulnerabilities.importers.redhat import RedhatImporter
from vulnerabilities.importers.retiredotnet import RetireDotnetImporter
from vulnerabilities.importers.suse_scores import SUSESeverityScoreImporter
from vulnerabilities.importers.ubuntu import UbuntuImporter
from vulnerabilities.importers.ubuntu_usn import UbuntuUSNImporter
from vulnerabilities.importers.xen import XenImporter
from vulnerabilities.improvers.default import DefaultImprover


class NVDImprover(DefaultImprover):
    importer = NVDImporter


class AlpineLinuxImprover(DefaultImprover):
    importer = AlpineImporter


class ApacheHTTPDImprover(DefaultImprover):
    importer = ApacheHTTPDImporter


class ApacheKafkaImprover(DefaultImprover):
    importer = ApacheKafkaImporter


class ApacheTomcatImprover(DefaultImprover):
    importer = ApacheTomcatImporter


class ArchLinuxImprover(DefaultImprover):
    importer = ArchlinuxImporter


class DebianImprover(DefaultImprover):
    importer = DebianImporter


class DebianOvalImprover(DefaultImprover):
    importer = DebianOvalImporter


class ElixirSecurityImprover(DefaultImprover):
    importer = ElixirSecurityImporter


class FireEyeImprover(DefaultImprover):
    importer = FireyeImporter


class GentooImprover(DefaultImprover):
    importer = GentooImporter


class GitHubAPIImprover(DefaultImprover):
    importer = GitHubAPIImporter


class GitLabAPIImprover(DefaultImprover):
    importer = GitLabAPIImporter


class IstioImprover(DefaultImprover):
    importer = IstioImporter


class MozillaImprover(DefaultImprover):
    importer = MozillaImporter


class NginxImprover(DefaultImprover):
    importer = NginxImporter


class NpmImprover(DefaultImprover):
    importer = NpmImporter


class OpensslImprover(DefaultImprover):
    importer = OpensslImporter


class PostgreSQLImprover(DefaultImprover):
    importer = PostgreSQLImporter


class ProjectKBMSRImprover(DefaultImprover):
    importer = ProjectKBMSRImporter


class PyPaImprover(DefaultImprover):
    importer = PyPaImporter


class PyPIImprover(DefaultImprover):
    importer = PyPIImporter


class RedhatImprover(DefaultImprover):
    importer = RedhatImporter


class RetireDotnetImprover(DefaultImprover):
    importer = RetireDotnetImporter


class SUSESeverityScoreImprover(DefaultImprover):
    importer = SUSESeverityScoreImporter


class UbuntuImprover(DefaultImprover):
    importer = UbuntuImporter


class UbuntuUSNImprover(DefaultImprover):
    importer = UbuntuUSNImporter


class XenImprover(DefaultImprover):
    importer = XenImporter
