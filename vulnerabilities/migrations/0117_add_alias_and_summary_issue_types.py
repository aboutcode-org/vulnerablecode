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
import vulnerabilities.models


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0116_advisoryv2_advisory_content_hash"),
    ]

    operations = [
        migrations.AlterField(
            model_name="advisorytodo",
            name="issue_type",
            field=models.CharField(
                choices=vulnerabilities.models.ISSUE_TYPE_CHOICES,
                db_index=True,
                help_text="Select the issue that needs to be addressed from the available options.",
                max_length=50,
            ),
        ),
        migrations.AlterField(
            model_name="advisorytodov2",
            name="issue_type",
            field=models.CharField(
                choices=vulnerabilities.models.ISSUE_TYPE_CHOICES,
                db_index=True,
                help_text="Select the issue that needs to be addressed from the available options.",
                max_length=50,
            ),
        ),
    ]
