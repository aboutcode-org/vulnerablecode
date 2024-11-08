from django.db import migrations, models
import django.db.models.deletion
from aboutcode.pipeline import LoopProgress

def split_packagerelatedvulnerability(apps, schema_editor):
    PackageRelatedVulnerability = apps.get_model('vulnerabilities', 'PackageRelatedVulnerability')
    FixingPackageRelatedVulnerability = apps.get_model('vulnerabilities', 'FixingPackageRelatedVulnerability')
    AffectedByPackageRelatedVulnerability = apps.get_model('vulnerabilities', 'AffectedByPackageRelatedVulnerability')

    obsolete_package_relation_query = PackageRelatedVulnerability.objects.all()
    obsolete_package_relation_query_count = obsolete_package_relation_query.count()
    print(f"\nMigrating {obsolete_package_relation_query_count:,d} old package vulnerability relationship.")

    progress = LoopProgress(
        total_iterations=obsolete_package_relation_query_count,
        progress_step=1,
        logger=print,
        )
    fixing_packages = []
    affected_packages = []
    for prv in progress.iter(obsolete_package_relation_query.iterator(chunk_size=10000)):
        if prv.fix:
            fp = FixingPackageRelatedVulnerability(
                package=prv.package,
                vulnerability=prv.vulnerability,
                created_by=prv.created_by,
                confidence=prv.confidence,
            )
            fixing_packages.append(fp)
        else:
            ap = AffectedByPackageRelatedVulnerability(
                package=prv.package,
                vulnerability=prv.vulnerability,
                created_by=prv.created_by,
                confidence=prv.confidence,
            )
            affected_packages.append(ap)
    
    FixingPackageRelatedVulnerability.objects.bulk_create(fixing_packages, batch_size=10000)
    AffectedByPackageRelatedVulnerability.objects.bulk_create(affected_packages, batch_size=10000)

def reverse_migration(apps, schema_editor):
    FixingPackageRelatedVulnerability = apps.get_model('vulnerabilities', 'FixingPackageRelatedVulnerability')
    AffectedByPackageRelatedVulnerability = apps.get_model('vulnerabilities', 'AffectedByPackageRelatedVulnerability')
    PackageRelatedVulnerability = apps.get_model('vulnerabilities', 'PackageRelatedVulnerability')

    fixing_package_relation_query = FixingPackageRelatedVulnerability.objects.all()
    fixing_package_relation_query_count = fixing_package_relation_query.count()
    print(f"\nMigrating {fixing_package_relation_query_count:,d} FixingPackage to old relationship.")

    progress = LoopProgress(
        total_iterations=fixing_package_relation_query_count,
        progress_step=1,
        logger=print,
        )
    for fpv in progress.iter(fixing_package_relation_query.iterator(chunk_size=10000)):
        PackageRelatedVulnerability.objects.create(
            package=fpv.package,
            vulnerability=fpv.vulnerability,
            created_by=fpv.created_by,
            confidence=fpv.confidence,
            fix=True,
        )

    affected_package_relation_query = AffectedByPackageRelatedVulnerability.objects.all()
    affected_package_relation_query_count = affected_package_relation_query.count()
    print(f"\nMigrating {affected_package_relation_query_count:,d} AffectedPackage to old relationship.")

    progress = LoopProgress(
        total_iterations=affected_package_relation_query_count,
        progress_step=1,
        logger=print,
        )
    for apv in progress.iter(affected_package_relation_query.iterator(chunk_size=10000)):
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
