#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from timeit import default_timer as timer

import django.db.models.deletion
from aboutcode.pipeline import LoopProgress
from aboutcode.pipeline import humanize_time
from django.db import migrations
from django.db import models

"""
Model and data migration to convert Advisory.aliases
JSON field to a concrete M2M Advisory-Alias relationship.

To achieve this following steps are executed in chronological order.
 - Create AdvisoryRelatedAlias model for Advisory-Alias M2M relationship.
 - Make unique_content_id non-nullable and a required field.
 - Make Alias.vulnerability field nullable, as vulnerability may not 
   exist for a corresponding alias during initial data collection.
 - Rename existing Advisory.aliases JSON field to old_aliases.
 - Create a new Advisory.aliases M2M relation through AdvisoryRelatedAlias model.
 - Run a data migration to populate new M2M Advisory.aliases relation using 
    Advisory.old_aliases data.
 - Delete Advisory.old_aliases field.

"""


def bulk_update(model, items, fields, logger):
    item_count = 0
    if items:
        try:
            model.objects.bulk_update(objs=items, fields=fields)
            item_count += len(items)
        except Exception as e:
            logger(f"Error updating Advisory: {e}")
    return item_count


def bulk_create(model, items, logger):
    item_count = 0
    if items:
        try:
            model.objects.bulk_create(objs=items)
            item_count += len(items)
        except Exception as e:
            logger(f"Error creating AdvisoryRelatedAlias: {e}")
    return item_count


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0089_alter_advisory_unique_content_id"),
    ]

    def populate_new_advisory_aliases_field(apps, schema_editor):
        """Populate the new Advisory.aliases relation using old_aliases JSON data."""
        migration_start_time = timer()
        Advisory = apps.get_model("vulnerabilities", "Advisory")
        Alias = apps.get_model("vulnerabilities", "Alias")
        AdvisoryRelatedAlias = apps.get_model("vulnerabilities", "AdvisoryRelatedAlias")
        advisories = Advisory.objects.all()
        aliases = {i.alias: i for i in Alias.objects.all()}

        chunk_size = 5000
        advisories_count = advisories.count()
        batch_size = 5000
        relation_to_create = []
        advisory_alias_relation_count = 0
        progress = LoopProgress(
            total_iterations=advisories_count,
            logger=print,
            progress_step=1,
        )
        print(f"\nPopulate new advisory aliases relationship.")
        for advisory in progress.iter(advisories.iterator(chunk_size=chunk_size)):
            advisory_alias_relations = [
                AdvisoryRelatedAlias(advisory=advisory, alias=aliases[alias])
                for alias in advisory.old_aliases
                if alias in aliases
            ]
            relation_to_create.extend(advisory_alias_relations)

            if len(relation_to_create) > batch_size:
                advisory_alias_relation_count += bulk_create(
                    model=AdvisoryRelatedAlias,
                    items=relation_to_create,
                    logger=print,
                )
                relation_to_create.clear()

        advisory_alias_relation_count += bulk_create(
            model=AdvisoryRelatedAlias,
            items=relation_to_create,
            logger=print,
        )
        migration_run_time = timer() - migration_start_time
        print(
            f"\nSuccessfully created {advisory_alias_relation_count} advisory-alias relationship."
        )
        print(f"\nData Migration: completed in {humanize_time(migration_run_time)}")

    def reverse_populate_new_advisory_aliases_field(apps, schema_editor):
        """Use the Advisory.aliases relation to populate old_aliases JSON field."""
        migration_start_time = timer()
        Advisory = apps.get_model("vulnerabilities", "Advisory")
        advisories = Advisory.objects.prefetch_related("aliases").all()

        updated_advisory_count = 0
        batch_size = 5000
        chunk_size = 5000
        advisory_to_update = []
        progress = LoopProgress(
            total_iterations=advisories.count(),
            logger=print,
            progress_step=1,
        )
        print(f"\nReverse alias migration to M2M relation.")
        for advisory in progress.iter(advisories.iterator(chunk_size=chunk_size)):
            aliases = advisory.aliases.all()
            advisory.old_aliases = [alias.alias for alias in aliases]
            advisory_to_update.append(advisory)

            if len(advisory_to_update) > batch_size:
                updated_advisory_count += bulk_update(
                    model=Advisory,
                    items=advisory_to_update,
                    fields=["old_aliases"],
                    logger=print,
                )
                advisory_to_update.clear()

        updated_advisory_count += bulk_update(
            model=Advisory,
            items=advisory_to_update,
            fields=["old_aliases"],
            logger=print,
        )

        migration_run_time = timer() - migration_start_time
        print(
            f"\nSuccessfully reversed the alias relationship for {updated_advisory_count} advisories."
        )
        print(f"\nData Migration: completed in {humanize_time(migration_run_time)}")

    operations = [
        migrations.CreateModel(
            name="AdvisoryRelatedAlias",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "advisory",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="vulnerabilities.advisory"
                    ),
                ),
                (
                    "alias",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="vulnerabilities.alias"
                    ),
                ),
            ],
            options={
                "unique_together": {("advisory", "alias")},
            },
        ),
        migrations.AlterField(
            model_name="advisory",
            name="unique_content_id",
            field=models.CharField(
                help_text="A 64 character unique identifier for the content of the advisory since we use sha256 as hex",
                max_length=64,
                blank=False,
                null=False,
            ),
        ),
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
            field=models.ManyToManyField(
                related_name="advisories",
                through="vulnerabilities.AdvisoryRelatedAlias",
                to="vulnerabilities.alias",
            ),
        ),
        migrations.RunPython(
            code=populate_new_advisory_aliases_field,
            reverse_code=reverse_populate_new_advisory_aliases_field,
        ),
        migrations.RemoveField(
            model_name="advisory",
            name="old_aliases",
        ),
    ]
