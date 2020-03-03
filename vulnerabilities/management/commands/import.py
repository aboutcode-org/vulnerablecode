#
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

from django.core.management.base import BaseCommand, CommandError

from vulnerabilities import data_dump as dd
from vulnerabilities.scraper import debian, ubuntu, archlinux, npm, ruby, rust, safety_db

IMPORTERS = {
    'safetydb': lambda: safety_db.import_vulnerabilities(),
    'rust': lambda: dd.rust_dump(rust.import_vulnerabilities()),
    'ruby': lambda: dd.ruby_dump(ruby.import_vulnerabilities()),
    'npm': lambda: dd.npm_dump(npm.scrape_vulnerabilities()),
    'debian': lambda: dd.debian_dump(debian.scrape_vulnerabilities()),
    'ubuntu': lambda: dd.ubuntu_dump(ubuntu.scrape_cves()),
    'archlinux': lambda: dd.archlinux_dump(archlinux.scrape_vulnerabilities())
}


class Command(BaseCommand):
    help = 'Import vulnerability data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--list',
            action='store_true',
            help='List available data sources')

        parser.add_argument('--all', action='store_true',
                            help='Import data from all available sources')

        parser.add_argument('sources', nargs='*',
                            help='Data sources from which to import')

    def handle(self, *args, **options):
        if options['list']:
            self.list_sources()
            return

        if options['all']:
            self.import_data(IMPORTERS.keys())
            return

        sources = options['sources']
        if not sources:
            raise CommandError(
                'Please provide at least one data source to import from or use "--all".')

        self.validate_sources(sources)
        self.import_data(sources)

    def validate_sources(self, sources):
        unknown = ', '.join([s for s in sources if s not in IMPORTERS.keys()])
        if unknown:
            raise CommandError(f'Unknown data sources: {unknown}')

    def list_sources(self):
        self.stdout.write(
            'Vulnerability data can be imported from the following sources:')
        self.stdout.write(', '.join(IMPORTERS.keys()))

    def import_data(self, sources):
        for src in sources:
            self.stdout.write(f'Importing data from {src}')
            IMPORTERS[src]()
            self.stdout.write(self.style.SUCCESS(f'Successfully imported data from {src}'))
