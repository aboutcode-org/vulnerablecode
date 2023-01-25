#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.db import migrations

from vulnerabilities.severity_systems import SCORING_SYSTEMS

class Migration(migrations.Migration):

    def remove_advisories(apps, schema_editor):
        Advisory = apps.get_model("vulnerabilities", "Advisory")
        deletables = []
        for advisory in Advisory.objects.iterator(chunk_size=1000):
            for ref in advisory.references:
                if not ref["url"]:
                    deletables.append(advisory.pk)
                    break
                for sev in ref["severities"]:
                    if sev["system"] not in SCORING_SYSTEMS:
                        deletables.append(advisory.pk)
                        break
        Advisory.objects.filter(pk__in=deletables).delete()            

    dependencies = [
        ("vulnerabilities", "0037_advisory_weaknesses_weakness"),
    ]

    operations = [
        migrations.RunPython(remove_advisories, reverse_code=migrations.RunPython.noop),
    ]