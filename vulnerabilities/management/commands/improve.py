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

from vulnerabilities.improve_runner import ImproveRunner
from vulnerabilities.improvers import IMPROVERS_REGISTRY


class Command(BaseCommand):
    help = "Improve vulnerability data"

    def add_arguments(self, parser):
        parser.add_argument(
            "--list",
            action="store_true",
            help="List available improvers",
        )
        parser.add_argument(
            "--all", action="store_true", help="Improve data from all available improvers"
        )
        parser.add_argument("sources", nargs="*", help="Fully qualified improver name to run")

    def handle(self, *args, **options):
        try:
            if options["list"]:
                self.list_sources()
            elif options["all"]:
                self.improve_data(IMPROVERS_REGISTRY.values())
            else:
                sources = options["sources"]
                if not sources:
                    raise CommandError(
                        'Please provide at least one improver to run or use "--all".'
                    )
                self.improve_data(validate_improvers(sources))
        except KeyboardInterrupt:
            raise CommandError("Keyboard interrupt received. Stopping...")

    def list_sources(self):
        improvers = list(IMPROVERS_REGISTRY)
        self.stdout.write("Vulnerability data can be processed by these available improvers:\n")
        self.stdout.write("\n".join(improvers))

    def improve_data(self, improvers):
        failed_improvers = []

        for improver in improvers:
            self.stdout.write(f"Improving data using {improver.qualified_name}")
            try:
                ImproveRunner(improver_class=improver).run()
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Successfully improved data using {improver.qualified_name}"
                    )
                )
            except Exception:
                failed_improvers.append(improver.qualified_name)
                traceback.print_exc()
                self.stdout.write(
                    self.style.ERROR(
                        f"Failed to run improver {improver.qualified_name}. Continuing..."
                    )
                )

        if failed_improvers:
            raise CommandError(f"{len(failed_improvers)} failed!: {','.join(failed_improvers)}")


def validate_improvers(sources):
    improvers = []
    unknown_sources = []
    for source in sources:
        try:
            improvers.append(IMPROVERS_REGISTRY[source])
        except KeyError:
            unknown_sources.append(source)
    if unknown_sources:
        raise CommandError(f"Unknown sources: {unknown_sources}")

    return improvers
