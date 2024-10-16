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
        migrations.AlterField(
            model_name="advisory",
            name="created_by",
            field=models.CharField(
                help_text="Fully qualified name of the importer prefixed with themodule name importing the advisory. Eg:vulnerabilities.pipeline.nginx_importer.NginxImporterPipeline",
                max_length=100,
            ),
        ),
        migrations.CreateModel(
            name="FixingPackageRelatedVulnerability",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "created_by",
                    models.CharField(
                        blank=True,
                        help_text="Fully qualified name of the improver prefixed with the module name responsible for creating this relation. Eg: vulnerabilities.importers.nginx.NginxBasicImprover",
                        max_length=100,
                    ),
                ),
                (
                    "confidence",
                    models.PositiveIntegerField(
                        default=100,
                        help_text="Confidence score for this relation",
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(100),
                        ],
                    ),
                ),
                (
                    "package",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="vulnerabilities.package"
                    ),
                ),
                (
                    "vulnerability",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="vulnerabilities.vulnerability",
                    ),
                ),
            ],
            options={
                "verbose_name_plural": "Fixing Package Related Vulnerabilities",
                "ordering": ["package", "vulnerability"],
                "abstract": False,
                "unique_together": {("package", "vulnerability")},
            },
        ),
        migrations.CreateModel(
            name="AffectedByPackageRelatedVulnerability",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                (
                    "created_by",
                    models.CharField(
                        blank=True,
                        help_text="Fully qualified name of the improver prefixed with the module name responsible for creating this relation. Eg: vulnerabilities.importers.nginx.NginxBasicImprover",
                        max_length=100,
                    ),
                ),
                (
                    "confidence",
                    models.PositiveIntegerField(
                        default=100,
                        help_text="Confidence score for this relation",
                        validators=[
                            django.core.validators.MinValueValidator(0),
                            django.core.validators.MaxValueValidator(100),
                        ],
                    ),
                ),
                (
                    "package",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="vulnerabilities.package"
                    ),
                ),
                (
                    "vulnerability",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="vulnerabilities.vulnerability",
                    ),
                ),
            ],
            options={
                "verbose_name_plural": "Affected By Package Related Vulnerabilities",
                "ordering": ["package", "vulnerability"],
                "abstract": False,
                "unique_together": {("package", "vulnerability")},
            },
        ),
        migrations.RunPython(split_packagerelatedvulnerability, reverse_migration),
    ]
