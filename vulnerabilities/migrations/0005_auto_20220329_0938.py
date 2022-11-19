
import hashlib
import json

from django.db import migrations


class Migration(migrations.Migration):
    def md5hash(apps, schema_editor):
        Advisory = apps.get_model("vulnerabilities", "Advisory")
        for advisory in Advisory.objects.all():
            checksum = hashlib.md5()
            for field in (advisory.summary, advisory.affected_packages, advisory.references):
                value = json.dumps(field, separators=(",", ":")).encode("utf-8")
                checksum.update(value)
            advisory.unique_content_id = checksum.hexdigest()
            advisory.save()

    dependencies = [
        ("vulnerabilities", "0004_advisory_unique_content_id"),
    ]

    operations = [
        migrations.RunPython(md5hash),
    ]
