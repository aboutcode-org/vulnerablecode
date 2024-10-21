#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0040_remove_advisory_date_improved_advisory_date_imported"),
    ]

    def remove_vulns_with_empty_aliases(apps, _):
        Vulnerability = apps.get_model("vulnerabilities", "Vulnerability")
        Package = apps.get_model("vulnerabilities", "Package")
        packages = []
        vulnerabilities = []
        for vuln in Vulnerability.objects.filter(aliases=None).prefetch_related(
                "packages"
        ):
            # Delete packages associated with that vulnerability
            for package in vuln.packages.all():
                packages.append(package.id)
            vulnerabilities.append(vuln.id)

        Vulnerability.objects.filter(id__in=vulnerabilities).delete()
        Package.objects.filter(id__in=packages).delete()

    operations = [
        migrations.RunPython(remove_vulns_with_empty_aliases, reverse_code=migrations.RunPython.noop),
    ]
