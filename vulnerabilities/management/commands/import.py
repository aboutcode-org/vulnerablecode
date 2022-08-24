#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import traceback

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importers import IMPORTERS_REGISTRY


class Command(BaseCommand):
    help = "Import vulnerability data"

    def add_arguments(self, parser):
        parser.add_argument(
            "--list",
            action="store_true",
            help="List available importers",
        )
        parser.add_argument("--all", action="store_true", help="Run all available importers")

        parser.add_argument(
            "--all_in_parallel", action="store_true", help="Run all available importers in parallel"
        )

        parser.add_argument("sources", nargs="*", help="Fully qualified importer name to run")

    def handle(self, *args, **options):
        if options["list"]:
            self.list_sources()
            return

        if options["all"]:
            self.import_data(IMPORTERS_REGISTRY.values())
            return

        sources = options["sources"]
        if not sources:
            raise CommandError('Please provide at least one importer to run or use "--all".')

        self.import_data(validate_importers(sources))

    def list_sources(self):
        importers = list(IMPORTERS_REGISTRY)
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
            importers.append(IMPORTERS_REGISTRY[source])
        except KeyError:
            unknown_sources.append(source)
    if unknown_sources:
        raise CommandError(f"Unknown sources: {unknown_sources}")

    return importers
