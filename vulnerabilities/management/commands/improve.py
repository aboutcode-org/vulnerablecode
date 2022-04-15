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
        if options["list"]:
            self.list_sources()
            return

        if options["all"]:
            self.improve_data(IMPROVERS_REGISTRY.values())
            return

        sources = options["sources"]
        if not sources:
            raise CommandError('Please provide at least one improver to run or use "--all".')

        self.improve_data(validate_improvers(sources))

    def list_sources(self):
        improvers = list(IMPROVERS_REGISTRY)
        self.stdout.write("Vulnerability data can be processed by these available improvers:\n")
        self.stdout.write("\n".join(improvers))

    def improve_data(self, improvers):
        failed_improvers = []

        for improver in improvers:
            self.stdout.write(f"Improving data using {improver.qualified_name}")
            try:
                ImproveRunner(improver).run()
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
