# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.


from vulnerabilities.importers.alpine_linux import AlpineDataSource
from vulnerabilities.importers.apache_httpd import ApacheHTTPDDataSource
from vulnerabilities.importers.apache_kafka import ApacheKafkaDataSource
from vulnerabilities.importers.apache_tomcat import ApacheTomcatDataSource
from vulnerabilities.importers.archlinux import ArchlinuxDataSource
from vulnerabilities.importers.debian import DebianDataSource
from vulnerabilities.importers.debian_oval import DebianOvalDataSource
from vulnerabilities.importers.elixir_security import ElixirSecurityDataSource
from vulnerabilities.importers.gentoo import GentooDataSource
from vulnerabilities.importers.github import GitHubAPIDataSource
from vulnerabilities.importers.kaybee import KaybeeDataSource
from vulnerabilities.importers.nginx import NginxDataSource
from vulnerabilities.importers.npm import NpmDataSource
from vulnerabilities.importers.nvd import NVDDataSource
from vulnerabilities.importers.openssl import OpenSSLDataSource
from vulnerabilities.importers.postgresql import PostgreSQLDataSource
from vulnerabilities.importers.project_kb_msr2019 import ProjectKBMSRDataSource
from vulnerabilities.importers.redhat import RedhatDataSource
from vulnerabilities.importers.retiredotnet import RetireDotnetDataSource
from vulnerabilities.importers.ruby import RubyDataSource
from vulnerabilities.importers.rust import RustDataSource
from vulnerabilities.importers.safety_db import SafetyDbDataSource
from vulnerabilities.importers.suse_backports import SUSEBackportsDataSource
from vulnerabilities.importers.suse_scores import SUSESeverityScoreDataSource
from vulnerabilities.importers.ubuntu import UbuntuDataSource
from vulnerabilities.importers.ubuntu_usn import UbuntuUSNDataSource
from vulnerabilities.importers.apache_tomcat import ApacheTomcatDataSource
from vulnerabilities.importers.vulcodes import VulCodeDataSource
