#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from aboutcode.pipeline import LoopProgress
from django.db import migrations
from django.db import models
import django.db.models.deletion

"""
Model and data migration for converting the Advisory aliases
JSON field to a concrete M2M Advisory Alias relationship.
"""

def bulk_update(model, items, fields, logger):
    item_count = 0
    if items:
        try:
            model.objects.bulk_update(objs=items, fields=fields)
            item_count += len(items)
        except Exception as e:
            logger(f"Error updating Advisory: {e}")
        items.clear()
    return item_count


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0088_fix_alpine_purl_type"),
    ]

    def populate_new_advisory_aliases_field(apps, schema_editor):
        Advisory = apps.get_model("vulnerabilities", "Advisory")
        Alias = apps.get_model("vulnerabilities", "Alias")
        advisories = Advisory.objects.all()

        chunk_size = 10000
        advisories_count = advisories.count()
        print(f"\nPopulate new advisory aliases relationship.")
        progress = LoopProgress(
            total_iterations=advisories_count,
            logger=print,
            progress_step=1,
        )
        for advisory in progress.iter(advisories.iterator(chunk_size=chunk_size)):
            aliases = Alias.objects.filter(alias__in=advisory.old_aliases)
            advisory.aliases.set(aliases)

    def reverse_populate_new_advisory_aliases_field(apps, schema_editor):
        Advisory = apps.get_model("vulnerabilities", "Advisory")
        advisories = Advisory.objects.all()

        updated_advisory_count = 0
        batch_size = 10000
        chunk_size = 10000
        updated_advisory = []
        progress = LoopProgress(
            total_iterations=advisories.count(),
            logger=print,
            progress_step=1,
        )
        for advisory in progress.iter(advisories.iterator(chunk_size=chunk_size)):
            aliases = advisory.aliases.all()
            advisory.old_aliases = [alias.alias for alias in aliases]
            updated_advisory.append(advisory)

            if len(updated_advisory) > batch_size:
                updated_advisory_count += bulk_update(
                    model=Advisory,
                    items=updated_advisory,
                    fields=["old_aliases"],
                    logger=print,
                )

        updated_advisory_count += bulk_update(
            model=Advisory,
            items=updated_advisory,
            fields=["old_aliases"],
            logger=print,
        )

    operations = [
        # Make vulnerability relation optional
        migrations.AlterField(
            model_name="alias",
            name="vulnerability",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="aliases",
                to="vulnerabilities.vulnerability",
            ),
        ),

        # Rename aliases field to old_aliases
        migrations.AlterModelOptions(
            name="advisory",
            options={"ordering": ["date_published", "unique_content_id"]},
        ),
        migrations.AlterUniqueTogether(
            name="advisory",
            unique_together={("unique_content_id", "date_published", "url")},
        ),
        migrations.RenameField(
            model_name="advisory",
            old_name="aliases",
            new_name="old_aliases",
        ),
        migrations.AddField(
            model_name="advisory",
            name="aliases",
            field=models.ManyToManyField(related_name="advisories", to="vulnerabilities.alias"),
        ),
        # Populate the new M2M aliases relation
        migrations.RunPython(
            code=populate_new_advisory_aliases_field,
            reverse_code=reverse_populate_new_advisory_aliases_field,
        ),
        # Delete JSON aliases field
        migrations.RemoveField(
            model_name="advisory",
            name="old_aliases",
        ),
    ]
