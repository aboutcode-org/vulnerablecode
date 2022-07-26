from django.db import migrations

class Migration(migrations.Migration):

    def update_cpe_url(apps, schema_editor):
        """
        Update the CPE URL for all vulnerabilities.
        """
        Reference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        for reference in Reference.objects.filter(reference_id__startswith="cpe", url=""):
            cpe = reference.reference_id
            base_url = 'https://nvd.nist.gov/vuln/search/results'
            params = '?adv_search=true&isCpeNameSearch=true'
            vuln_url = f'{base_url}{params}&query={cpe}'
            reference.url = vuln_url
            # check if url and cpe already exists
            if not Reference.objects.filter(reference_id=cpe, url=vuln_url).exists():
                reference.save()
            # remove the reference with an empty url if it already exists
            else:
                reference.delete()

    dependencies = [
        ('vulnerabilities', '0015_alter_vulnerabilityseverity_unique_together_and_more'),
    ]

    operations = [
        migrations.RunPython(update_cpe_url, migrations.RunPython.noop),
    ]
