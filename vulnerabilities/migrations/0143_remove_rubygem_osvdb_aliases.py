#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.db import migrations

"""
Remove the OSVDB-derived aliases imported from the rubygem data sources.

The rubysec advisory data contains legacy references to the defunct OSVDB
database, and these were imported as "OSV-<number>" aliases. These are not
public aliases and collide with the modern OSV.dev namespace. Genuine
OSV.dev identifiers have the form "OSV-<year>-<number>" with two hyphens
and are preserved.

See https://github.com/aboutcode-org/vulnerablecode/issues/2421
"""

OSVDB_DERIVED_ALIAS_REGEX = r"^OSV-\d+$"


def remove_osvdb_aliases(apps, schema_editor):
    Alias = apps.get_model("vulnerabilities", "Alias")
    Alias.objects.filter(alias__regex=OSVDB_DERIVED_ALIAS_REGEX).delete()

    AdvisoryAlias = apps.get_model("vulnerabilities", "AdvisoryAlias")
    AdvisoryAlias.objects.filter(alias__regex=OSVDB_DERIVED_ALIAS_REGEX).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0142_advisoryv2_is_curation_advisoryv2_resolves_todos"),
    ]

    operations = [
        migrations.RunPython(remove_osvdb_aliases, reverse_code=migrations.RunPython.noop),
    ]
