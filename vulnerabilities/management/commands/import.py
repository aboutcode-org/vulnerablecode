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

import traceback

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from vulnerabilities.importers import IMPORTER_REGISTRY
from vulnerabilities.import_runner import ImportRunner


class Command(BaseCommand):
    help = "Import vulnerability data"

    def add_arguments(self, parser):
        parser.add_argument(
            "--list",
            action="store_true",
            help="List available importers",
        )
        parser.add_argument("--all", action="store_true", help="Run all available importers")

        parser.add_argument("sources", nargs="*", help="Fully qualified importer name to run")

    def handle(self, *args, **options):
        if options["list"]:
            self.list_sources()
            return

        if options["all"]:
            self.import_data(IMPORTER_REGISTRY.values())
            return

        sources = options["sources"]
        if not sources:
            raise CommandError('Please provide at least one importer to run or use "--all".')

        self.import_data(validate_importers(sources))

    def list_sources(self):
        importers = list(IMPORTER_REGISTRY)
        self.stdout.write("Vulnerability data can be imported from the following importers:")
        self.stdout.write("\n".join(importers))

    def import_data(self, importers):
        """
        Run the given ``importers``. The ``importers`` are expected to be class
        names for the importers.
        """
        failed_importers = []

        for importer in importers:
            self.stdout.write(f"Importing data using {importer.qualified_name}")
            try:
                ImportRunner(importer).run()
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Successfully imported data using {importer.qualified_name}"
                    )
                )
            except Exception:
                failed_importers.append(importer.qualified_name)
                traceback.print_exc()
                self.stdout.write(
                    self.style.ERROR(
                        f"Failed to run importer {importer.qualified_name}. Continuing..."
                    )
                )

        if failed_importers:
            raise CommandError(f"{len(failed_importers)} failed!: {','.join(failed_importers)}")


def validate_importers(sources):
    importers = []
    unknown_sources = []
    for source in sources:
        try:
            importers.append(IMPORTER_REGISTRY[source])
        except KeyError:
            unknown_sources.append(source)
    if unknown_sources:
        raise CommandError(f"Unknown sources: {unknown_sources}")

    return importers
