from django.db import migrations, models
import django.db.models.deletion
from django.core.validators import MaxValueValidator, MinValueValidator
from vulnerabilities.improver import MAX_CONFIDENCE

def split_packagerelatedvulnerability(apps, schema_editor):
    PackageRelatedVulnerability = apps.get_model('vulnerabilities', 'PackageRelatedVulnerability')
    FixingPackageRelatedVulnerability = apps.get_model('vulnerabilities', 'FixingPackageRelatedVulnerability')
    AffectedByPackageRelatedVulnerability = apps.get_model('vulnerabilities', 'AffectedByPackageRelatedVulnerability')

    for prv in PackageRelatedVulnerability.objects.all():
        if prv.fix:
            FixingPackageRelatedVulnerability.objects.create(
                package=prv.package,
                vulnerability=prv.vulnerability,
                created_by=prv.created_by,
                confidence=prv.confidence,
            )
        else:
            AffectedByPackageRelatedVulnerability.objects.create(
                package=prv.package,
                vulnerability=prv.vulnerability,
                created_by=prv.created_by,
                confidence=prv.confidence,
            )

def reverse_migration(apps, schema_editor):
    FixingPackageRelatedVulnerability = apps.get_model('vulnerabilities', 'FixingPackageRelatedVulnerability')
    AffectedByPackageRelatedVulnerability = apps.get_model('vulnerabilities', 'AffectedByPackageRelatedVulnerability')
    PackageRelatedVulnerability = apps.get_model('vulnerabilities', 'PackageRelatedVulnerability')

    for fpv in FixingPackageRelatedVulnerability.objects.all():
        PackageRelatedVulnerability.objects.create(
            package=fpv.package,
            vulnerability=fpv.vulnerability,
            created_by=fpv.created_by,
            confidence=fpv.confidence,
            fix=True,
        )

    for apv in AffectedByPackageRelatedVulnerability.objects.all():
        PackageRelatedVulnerability.objects.create(
            package=apv.package,
            vulnerability=apv.vulnerability,
            created_by=apv.created_by,
            confidence=apv.confidence,
            fix=False,
        )

class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0070_alter_advisory_created_by_and_more"),
    ]

    operations = [
        migrations.RunPython(split_packagerelatedvulnerability, reverse_migration),
    ]
