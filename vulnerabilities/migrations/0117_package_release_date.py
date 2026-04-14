#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from django.db import migrations
from django.db import models


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0116_advisoryv2_advisory_content_hash"),
    ]

    operations = [
        migrations.AddField(
            model_name="package",
            name="release_date",
            field=models.DateTimeField(
                blank=True,
                db_index=True,
                help_text="Date when this package version was released by the upstream package source.",
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="packagev2",
            name="release_date",
            field=models.DateTimeField(
                blank=True,
                db_index=True,
                help_text="Date when this package version was released by the upstream package source.",
                null=True,
            ),
        ),
    ]
