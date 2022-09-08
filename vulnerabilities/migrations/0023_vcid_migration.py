from django.db import migrations
from django.db.models import Q

from vulnerabilities.utils import build_vcid


class Migration(migrations.Migration):

    dependencies = [
        ('vulnerabilities', '0022_alter_vulnerability_vulnerability_id'),
    ]

    def save_vulnerability_id(apps, schema_editor):
        Vulnerabilities = apps.get_model("vulnerabilities", "Vulnerability")
        updatables = []
        for vulnerability in Vulnerabilities.objects.filter(~Q(vulnerability_id__startswith="VCID-")):
            vulnerability.vulnerability_id = build_vcid()
            updatables.append(vulnerability)
        # update in bulk, 500 at a time
        updated = Vulnerabilities.objects.bulk_update(
            objs=updatables, 
            fields=["vulnerability_id"], 
            batch_size=500,
        )
        print(f"Migrated {updated} vulnerabilities to new VCID")

    operations = [
        migrations.RunPython(save_vulnerability_id, migrations.RunPython.noop)
    ]
