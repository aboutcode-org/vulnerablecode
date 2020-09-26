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

import os
import json
import tempfile
from contextlib import contextmanager

from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from vulnerabilities import models

# See https://stackoverflow.com/a/24176022
@contextmanager
def cd(newdir):
    prevdir = os.getcwd()
    os.chdir(os.path.expanduser(newdir))
    try:
        yield
    finally:
        os.chdir(prevdir)


def get_vulcodes():

    vulcodes = models.Vulnerability.objects.filter(
        identifier__startswith="VULCODE"
    ).select_related()
    for vuln in vulcodes:
        yield {
            "identifier": vuln.identifier,
            "summary": vuln.summary,
            "references": [
                {
                    "url": ref.url,
                    "reference_id": ref.reference_id,
                }
                for ref in vuln.vulnerabilityreference_set.all()
            ],
            "vulnerable_packages": [pkg.package_url for pkg in vuln.vulnerable_to],
            "resolved_packages": [pkg.package_url for pkg in vuln.resolved_to],
        }


class Command(BaseCommand):
    help = "Push all VulCodes to remote repo"

    def add_arguments(self, parser):
        parser.add_argument(
            "remote_url",
            help="Example Value :`https://github.com/nexB/vulcodes.git`",
        )

    def handle(self, *args, **options):
        repo_url = options["remote_url"]
        # TODO; Do some validation of `repo_url` here
        push_data(repo_url)


def push_data(url):
    repo_location = tempfile.mkdtemp()
    with cd(repo_location):
        os.system(f"git clone {url}")
        # TODO: Don't hardcode `vulcodes`
        os.system("cd vulcodes")
        with cd("vulcodes"):
            for vulcode in get_vulcodes():
                with open(vulcode["identifier"] + ".json", "w") as f:
                    json.dump(vulcode, f, indent=4)

            os.system("git add .")
            os.system("git commit -s -m 'Vulcode Sync' ")
            os.system("git push")
