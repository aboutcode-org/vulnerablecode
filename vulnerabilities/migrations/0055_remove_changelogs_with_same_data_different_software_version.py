#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from collections import defaultdict
from django.db import migrations
from django.core.paginator import Paginator


class Migration(migrations.Migration):

    def remove_duped_changelogs(apps, schema_editor):
        PackageChangeLog = apps.get_model("vulnerabilities", "PackageChangeLog")
        VulnerabilityChangeLog = apps.get_model("vulnerabilities", "VulnerabilityChangeLog")

        models_list = [PackageChangeLog, VulnerabilityChangeLog]

        common_fields = ('actor_name', 'action_type', 'source_url')
        for model in models_list:
            record_groups = defaultdict(list)
            fields = set()
            key = tuple()
            if model == PackageChangeLog:
                fields = common_fields + ('package', 'related_vulnerability')
                all_records = model.objects.select_related("package").all()
            elif model == VulnerabilityChangeLog:
                fields = common_fields + ('vulnerability',)
                all_records = model.objects.select_related("vulnerability").all()

            print("Total number of records", all_records.count())
            for record in paginated(all_records):
                print(",", end="")
                key = tuple(getattr(record, attr) for attr in fields)
                record_groups[key].append(record.id)

            to_be_deleted = []
            for record_ids in record_groups.values():
                if len(record_ids) == 1:
                    continue
                print(".", end="")
                # We exclude the oldest ID which is the last one based on the standard 
                # ordering by decreasing the action time
                to_be_deleted.extend(record_ids[:-1])

            chunks = [to_be_deleted[x:x+10000] for x in range(0, len(to_be_deleted), 10000)]
            for chunk in chunks:
                model.objects.filter(id__in=chunk).delete()

    dependencies = [
        ("vulnerabilities", "0054_alter_packagechangelog_software_version_and_more"),
    ]

    operations = [
        migrations.RunPython(remove_duped_changelogs, reverse_code=migrations.RunPython.noop),
    ]


def paginated(qs, per_page=5000):
    """
    Iterate over a (large) QuerySet by chunks of ``per_page`` items.
    This technique is essential for preventing memory issues when iterating
    See these links for inspiration:
    https://nextlinklabs.com/resources/insights/django-big-data-iteration
    https://stackoverflow.com/questions/4222176/why-is-iterating-through-a-large-django-queryset-consuming-massive-amounts-of-me/
    """
    paginator = Paginator(qs, per_page=per_page)
    for page_number in paginator.page_range:
        page = paginator.page(page_number)
        for object in page.object_list:
            yield object
