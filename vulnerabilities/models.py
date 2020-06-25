#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import importlib
from datetime import datetime

from django.db import models
import django.contrib.postgres.fields as pgfields
from django.utils.translation import ugettext_lazy as _

from packageurl.contrib.django_models import PackageURLMixin
from packageurl import PackageURL

from vulnerabilities.data_source import DataSource

class Importer(models.Model):
    """
    Metadata and pointer to the implementation for a source of vulnerability data (aka security
    advisories)
    """
    name = models.CharField(max_length=100, unique=True, help_text='Name of the importer')

    license = models.CharField(
        max_length=100,
        blank=True,
        help_text='License of the vulnerability data',
    )

    last_run = models.DateTimeField(null=True, help_text='UTC Timestamp of the last run')

    data_source = models.CharField(
        max_length=100,
        help_text='Name of the data source implementation importable from vulnerabilities.importers'
    )
    data_source_cfg = pgfields.JSONField(
        null=False,
        default=dict,
        help_text='Implementation-specific configuration for the data source',
    )

    def make_data_source(self, batch_size: int, cutoff_date: datetime = None) -> DataSource:
        """
        Return a configured and ready to use instance of this importers data source implementation.

        batch_size - max. number of records to return on each iteration
        cutoff_date - optional timestamp of the oldest data to include in the import
        """
        importers_module = importlib.import_module('vulnerabilities.importers')
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


class Vulnerability(models.Model):
    """
    A software vulnerability with minimal information. Identifiers other than CVE ID are stored as
    VulnerabilityReference.
    """
    vuln_id = models.CharField(max_length=50, help_text='eg CVE ID, RUST SEC ID', unique=True, null=True)
    reference_ids = pgfields.JSONField() 

    # Whatever goes into vuln_id is a vulnerability identifier 
    # which is undivisible i.e atomic vulnerability id. All CVEs fit into this.
    
    # reference_ids are usually but not limited to `advisory` ids like USN-4399-1
    # https://usn.ubuntu.com/4399-1/.     
    # Contents of reference_ids are a name/id given to collection of 
    # other small vulnerbilties. For example USN-4399-1 refers to CVE-2020-8618, CVE-2020-8619

    def __str__(self):
        return self.cve_id or self.summary

    class Meta:
        verbose_name_plural = 'Vulnerabilities'


class VulnerabilityReference(models.Model):
    """
    A reference to a vulnerability such as a security advisory from a Linux distribution or language
    package manager.
    """
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE)    
    source = models.ForeignKey(
        Importer, on_delete=models.CASCADE)
    urls = pgfields.JSONField()
    summary = models.TextField()

    class Meta:
        unique_together = ('vulnerability', 'source')

class VulnerabilityScore(models.Model):
  vulnerability_reference = models.ForeignKey(VulnerabilityReference, on_delete=models.CASCADE)
  type = models.CharField(max_length=50, help_text='Vulnerability score type', blank=True)
  score = models.CharField(max_length=50)

class Package(PackageURLMixin):
    """
    A software package with links to relevant vulnerabilities.
    """
    vulnerabilities = models.ManyToManyField(to='Vulnerability', through='Vulnerability_Package_Relation')

    class Meta:
        unique_together = ('name', 'namespace', 'type', 'version', 'qualifiers', 'subpath')
    # Remove the `qualifers` and `set_package_url` overrides after
    # https://github.com/package-url/packageurl-python/pull/35 gets merged
    qualifiers = pgfields.JSONField(
        default=dict,
        help_text=_(
            'Extra qualifying data for a package such as the name of an OS, '
            'architecture, distro, etc.'
        ),
        null=True
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


class Vulnerability_Package_Relation(models.Model):
    """
    Relates a vulnerability to package(s) impacted by it.
    """
# {
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    package = models.ForeignKey(Package, on_delete=models.CASCADE)
    is_vulnerable = models.BooleanField()
# } till this point we have a consensus in this model

    version_range = models.CharField(max_length=50)

    class Meta:
        unique_together = ('vulnerability', 'package')