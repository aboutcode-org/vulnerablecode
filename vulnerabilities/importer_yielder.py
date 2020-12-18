# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from vulnerabilities.models import Importer

IMPORTER_REGISTRY = [
    {
        'name': 'rust',
        'license': 'cc0-1.0',
        'last_run': None,
        'data_source': 'RustDataSource',
        'data_source_cfg': {
            'branch': None,
            'repository_url': 'https://github.com/RustSec/advisory-db',
        },
    },
    {
        'name': 'alpine',
        'license': '',
        'last_run': None,
        'data_source': 'AlpineDataSource',
        'data_source_cfg': {
            'branch': None,
            'repository_url': 'https://gitlab.alpinelinux.org/alpine/infra/alpine-secdb',
        },
    },
    {
        'name': 'archlinux',
        'license': 'mit',
        'last_run': None,
        'data_source': 'ArchlinuxDataSource',
        'data_source_cfg': {
            'archlinux_tracker_url': 'https://security.archlinux.org/json'
        },
    },
    {
        'name': 'debian',
        'license': 'mit',
        'last_run': None,
        'data_source': 'DebianDataSource',
        'data_source_cfg': {
            'debian_tracker_url': 'https://security-tracker.debian.org/tracker/data/json'
        },
    },
#     {
#         'name': 'safetydb',
#         'license': 'cc-by-nc-4.0',
#         'last_run': None,
#         'data_source': 'SafetyDbDataSource',
#         'data_source_cfg': {
#             'url': 'https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json',  # nopep8
#             'etags': {}
#         },
#     },
    {
        'name': 'npm',
        'license': 'mit',
        'last_run': None,
        'data_source': 'NpmDataSource',
        'data_source_cfg': {
            'repository_url': 'https://github.com/nodejs/security-wg.git'
        },
    },
    {
        'name': 'ruby',
        'license': '',
        'last_run': None,
        'data_source': 'RubyDataSource',
        'data_source_cfg': {
            'repository_url': 'https://github.com/rubysec/ruby-advisory-db.git'
        },
    },
    {
        'name': 'ubuntu',
        'license': 'gpl-2.0',
        'last_run': None,
        'data_source': 'UbuntuDataSource',
        'data_source_cfg': {
            'etags': {},
            'releases': ['bionic', 'trusty', 'focal', 'eoan', 'xenial'],
        },
    },
    {
        'name': 'retiredotnet',
        'license': 'mit',
        'last_run': None,
        'data_source': 'RetireDotnetDataSource',
        'data_source_cfg': {
            'repository_url': 'https://github.com/RetireNet/Packages.git'
        },
    },
    {
        'name': 'suse_backports',
        'license': '',
        'last_run': None,
        'data_source': 'SUSEBackportsDataSource',
        'data_source_cfg': {
            'url': 'http://ftp.suse.com/pub/projects/security/yaml/',
            'etags': {},
        },
    },
    {
        'name': 'debian_oval',
        'license': '',
        'last_run': None,
        'data_source': 'DebianOvalDataSource',
        'data_source_cfg': {
            'etags': {},
            'releases': ['wheezy', 'stretch', 'jessie', 'buster'],
        },
    },
    {
        'name': 'redhat',
        'license': 'cc-by-4.0',
        'last_run': None,
        'data_source': 'RedhatDataSource',
        'data_source_cfg': {},
    },
    {
        'name': 'nvd',
        'license': '',
        'last_run': None,
        'data_source': 'NVDDataSource',
        'data_source_cfg': {
            'etags': {},
        },
    },
    {
        'name': 'gentoo',
        'license': '',
        'last_run': None,
        'data_source': 'GentooDataSource',
        'data_source_cfg': {
            'repository_url': 'https://anongit.gentoo.org/git/data/glsa.git'
        },
    },
    {
        'name': 'openssl',
        'license': '',
        'last_run': None,
        'data_source': 'OpenSSLDataSource',
        'data_source_cfg': {
            'etags': {}
        },
    },
    {
        'name': 'ubuntu_usn',
        'license': 'gpl-2.0',
        'last_run': None,
        'data_source': 'UbuntuUSNDataSource',
        'data_source_cfg': {
            'etags': {},
            'db_url': 'https://usn.ubuntu.com/usn-db/database-all.json.bz2'
        },
    },
    {
        'name': 'github',
        'license': '',
        'last_run': None,
        'data_source': 'GitHubAPIDataSource',
        'data_source_cfg': {
            'endpoint': 'https://api.github.com/graphql',
            'ecosystems': ['MAVEN', 'NUGET', 'COMPOSER', 'PIP', 'RUBYGEMS']
        }
    },
    {
        'name': 'msr2019',
        'license': 'apache-2.0',
        'last_run': None,
        'data_source': 'ProjectKBMSRDataSource',
        'data_source_cfg': {
            'etags': {}
        }
    },
    {
        'name': 'apache_httpd',
        'license': '',
        'last_run': None,
        'data_source': 'ApacheHTTPDDataSource',
        'data_source_cfg': {
            'etags': {}
        },
    },
    {
        'name': 'kaybee',
        'license': 'apache-2.0',
        'last_run': None,
        'data_source': 'KaybeeDataSource',
        'data_source_cfg': {
            'repository_url': 'https://github.com/SAP/project-kb.git',
            'branch': 'vulnerability-data'
        },
    },
    {
        'name': 'nginx',
        'license': '',
        'last_run': None,
        'data_source': 'NginxDataSource',
        'data_source_cfg': {
            'etags': {}
        },
    },
    {
        'name': 'postgresql',
        'license': '',
        'last_run': None,
        'data_source': 'PostgreSQLDataSource',
        'data_source_cfg': {},
    },
    {
        'name': 'elixir_security',
        'license': '',
        'last_run': None,
        'data_source': 'ElixirSecurityDataSource',
        'data_source_cfg': {
            'repository_url': 'https://github.com/dependabot/elixir-security-advisories'
        },
    },
    {
        'name': 'apache_tomcat',
        'license': '',
        'last_run': None,
        'data_source': 'ApacheTomcatDataSource',
        'data_source_cfg': {
            "etags": {}
        },
    },

]


def load_importers():

    for importer in IMPORTER_REGISTRY:
        imp, created = Importer.objects.get_or_create(
            name=importer['name'],
            data_source=importer['data_source'],
            license=importer['license'],
        )

        if created:
            # Sets the dynamic fields equal to the default values
            imp.data_source_cfg = importer['data_source_cfg']
            imp.last_run = importer['last_run']
            imp.save()
