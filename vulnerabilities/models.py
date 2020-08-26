#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import importlib
from datetime import datetime

from django.db import models
import django.contrib.postgres.fields as pgfields
from django.utils.translation import ugettext_lazy as _

from packageurl.contrib.django_models import PackageURLMixin
from packageurl import PackageURL

from vulnerabilities.data_source import DataSource


class Vulnerability(models.Model):
    """
    A software vulnerability with minimal information. Identifiers other than CVE ID are stored as
    VulnerabilityReference.
    """

    cve_id = models.CharField(max_length=50, help_text="CVE ID", unique=True, null=True)
    summary = models.TextField(help_text="Summary of the vulnerability", blank=True)
    cvss = models.FloatField(max_length=100, help_text="CVSS Score", null=True)

    @property
    def vulnerable_to(self):
        return self.packagerelatedvulnerability_set.filter(is_vulnerable=True)

    @property
    def resolved_to(self):
        return self.packagerelatedvulnerability_set.filter(is_vulnerable=False)

    def __str__(self):
        return self.cve_id or self.summary

    class Meta:
        verbose_name_plural = "Vulnerabilities"


class VulnerabilityReference(models.Model):
    """
    A reference to a vulnerability such as a security advisory from a Linux distribution or language
    package manager.
    """

    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    source = models.CharField(max_length=50, help_text="Source(s) name eg:NVD", blank=True)
    reference_id = models.CharField(
        max_length=50, help_text="Reference ID, eg:DSA-4465-1", blank=True
    )
    url = models.URLField(max_length=1024, help_text="URL of Vulnerability data", blank=True)

    class Meta:
        unique_together = ("vulnerability", "source", "reference_id", "url")

    def __str__(self):
        return f"{self.source} {self.reference_id} {self.url}"


class Package(PackageURLMixin):
    """
    A software package with links to relevant vulnerabilities.
    """

    vulnerabilities = models.ManyToManyField(
        to="Vulnerability", through="PackageRelatedVulnerability"
    )

    @property
    def vulnerable_to(self):
        return self.packagerelatedvulnerability_set.filter(is_vulnerable=True)

    @property
    def resolved_to(self):
        return self.packagerelatedvulnerability_set.filter(is_vulnerable=False)

    class Meta:
        unique_together = ("name", "namespace", "type", "version", "qualifiers", "subpath")

    # Remove the `qualifers` and `set_package_url` overrides after
    # https://github.com/package-url/packageurl-python/pull/35 gets merged
    qualifiers = pgfields.JSONField(
        default=dict,
        help_text=_(
            "Extra qualifying data for a package such as the name of an OS, "
            "architecture, distro, etc."
        ),
        null=True,
    )

    def set_package_url(self, package_url):
        """
        Set each field values to the values of the provided `package_url` string
        or PackageURL object. Existing values are overwritten including setting
        values to None for provided empty values.
        """
        if not isinstance(package_url, PackageURL):
            package_url = PackageURL.from_string(package_url)

        for field_name, value in package_url.to_dict().items():
            model_field = self._meta.get_field(field_name)

            if value and len(value) > model_field.max_length:
                raise ValidationError(_('Value too long for field "{}".'.format(field_name)))

            setattr(self, field_name, value or None)

    def __str__(self):
        return self.package_url


class PackageRelatedVulnerability(models.Model):

    package = models.ForeignKey(Package, on_delete=models.CASCADE)
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    is_vulnerable = models.BooleanField()

    class Meta:
        # Technically 'is_vulnerable' doesn't belong here. The idea is to
        # later filter out for a pairs of ('package', 'vulnerability') which have both
        # values of 'is_vulnerable' and ping the data providers to  resolve such entries.
        unique_together = ("package", "vulnerability", "is_vulnerable")


class ImportProblem(models.Model):

    conflicting_model = pgfields.JSONField()


class Importer(models.Model):
    """
    Metadata and pointer to the implementation for a source of vulnerability data (aka security
    advisories)
    """

    name = models.CharField(max_length=100, unique=True, help_text="Name of the importer")

    license = models.CharField(
        max_length=100, blank=True, help_text="License of the vulnerability data",
    )

    last_run = models.DateTimeField(null=True, help_text="UTC Timestamp of the last run")

    data_source = models.CharField(
        max_length=100,
        help_text="Name of the data source implementation importable from vulnerabilities.importers",  # nopep8
    )
    data_source_cfg = pgfields.JSONField(
        null=False,
        default=dict,
        help_text="Implementation-specific configuration for the data source",
    )

    def make_data_source(self, batch_size: int, cutoff_date: datetime = None) -> DataSource:
        """
        Return a configured and ready to use instance of this importers data source implementation.

        batch_size - max. number of records to return on each iteration
        cutoff_date - optional timestamp of the oldest data to include in the import
        """
        importers_module = importlib.import_module("vulnerabilities.importers")
        klass = getattr(importers_module, self.data_source)

        ds = klass(
            batch_size,
            last_run_date=self.last_run,
            cutoff_date=cutoff_date,
            config=self.data_source_cfg,
        )

        return ds

    def __str__(self):
        return self.name
