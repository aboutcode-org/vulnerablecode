from django.db import migrations
from packageurl import PackageURL

from vulnerabilities.severity_systems import SCORING_SYSTEMS

class Migration(migrations.Migration):

    def remove_advisories(apps, schema_editor):
        Advisory = apps.get_model("vulnerabilities", "Advisory")
        deletables = []
        for advisory in Advisory.objects.iterator(chunk_size=1000):
            print(advisory.pk)
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
        ("vulnerabilities", "0036_alter_package_package_url_and_more"),
    ]

    operations = [
        migrations.RunPython(remove_advisories, reverse_code=migrations.RunPython.noop),
    ]