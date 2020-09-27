#
# Copyright (c) nexB Inc. and others. All rights reserved.
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

from datetime import datetime

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from vulnerabilities.models import Importer
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importer_yielder import load_importers


class Command(BaseCommand):
    help = "Import vulnerability data"

    def add_arguments(self, parser):
        parser.add_argument(
            "--list",
            action="store_true",
            help="List available data sources",
        )
        parser.add_argument(
            "--all", action="store_true", help="Import data from all available sources"
        )

        parser.add_argument(
            "--cutoff-date",
            type=datetime.fromisoformat,
            help="ISO8601 formatted timestamp denoting the maximum age of vulnerability "
            "information to import.",
        )
        parser.add_argument("sources", nargs="*", help="Data sources from which to import")

        parser.add_argument(
            "--batch_size", help="The batch size to be used for bulk inserting data"
        )

        parser.add_argument(
            "--cv",
            action="store_true",
            help="This will import and assign id's to vulnerabilities without any identifiers",
        )

    def handle(self, *args, **options):
        # load_importers() seeds the DB with Importers
        load_importers()
        if options["list"]:
            self.list_sources()
            return

        if options["batch_size"]:
            self.batch_size = options["batch_size"]

        self.create_vulcodes = options["cv"]

        if options["all"]:
            self._import_data(Importer.objects.all(), options["cutoff_date"])
            return

        sources = options["sources"]
        if not sources:
            raise CommandError(
                'Please provide at least one data source to import from or use "--all".'
            )

        self.import_data(sources, options["cutoff_date"])

    def list_sources(self):
        importers = Importer.objects.all()
        self.stdout.write("Vulnerability data can be imported from the following sources:")
        self.stdout.write(", ".join([i.name for i in importers]))

    def import_data(self, names, cutoff_date):
        importers = []
        unknown_importers = set()
        # make sure all arguments are valid before running any importers
        for name in names:
            try:
                importers.append(Importer.objects.get(name=name))
            except Importer.DoesNotExist:
                unknown_importers.add(name)

        if unknown_importers:
            unknown_importers = ", ".join(unknown_importers)
            raise CommandError(f"Unknown data sources: {unknown_importers}")

        self._import_data(importers, cutoff_date)

    def _import_data(self, importers, cutoff_date):
        for importer in importers:
            self.stdout.write(f"Importing data from {importer.name}")
            batch_size = int(getattr(self, "batch_size", 10))
            ImportRunner(importer, batch_size).run(
                cutoff_date=cutoff_date, create_vulcodes=self.create_vulcodes
            )
            self.stdout.write(
                self.style.SUCCESS(f"Successfully imported data from {importer.name}")
            )
