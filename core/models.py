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

from django.db import models

from packageurl.contrib.django_models import PackageURLMixin


class Vulnerability(models.Model):
    """
    A software vulnerability with minimal information.
    Identifiers other than CVE ID are stored as VulnerabilityReference.
    """
    cve_id = models.CharField(max_length=50, help_text='CVE ID', unique=True, null=True)
    summary = models.TextField(help_text='Summary of the vulnerability', blank=True)
    cvss = models.FloatField(max_length=100, help_text='CVSS Score', null=True)

    def __str__(self):
        return self.summary


class VulnerabilityReference(models.Model):
    """
    A reference to a vulnerability such as a security advisory from
    a Linux distribution or language package manager.
    """
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE)
    source = models.CharField(
        max_length=50, help_text='Source(s) name eg:NVD', blank=True)
    reference_id = models.CharField(
        max_length=50, help_text='Reference ID, eg:DSA-4465-1', blank=True)
    url = models.URLField(
        max_length=1024, help_text='URL of Vulnerability data', blank=True)

    class Meta:
        unique_together = ('vulnerability', 'source', 'reference_id', 'url')

    def __str__(self):
        return self.source


class Package(PackageURLMixin):
    """
    A software package with minimal identifying information.
    Other identifiers are stored as PackageReference.
    """
    vulnerabilities = models.ManyToManyField(to='Vulnerability', through='ImpactedPackage')

    def __str__(self):
        return self.name


class ImpactedPackage(models.Model):
    """
    Relates a vulnerability to package(s) impacted by it.
    """
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    package = models.ForeignKey(Package, on_delete=models.CASCADE)

    class Meta:
        unique_together = ('vulnerability', 'package')


class ResolvedPackage(models.Model):
    """
    Relates a vulnerability to package(s) that contain
    a fix or resolution of this vulnerability.
    """
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.CASCADE)
    package = models.ForeignKey(Package, on_delete=models.CASCADE)


class PackageReference(models.Model):
    """
    One or more identifiers and references for a software package
    in a package repository, such as a Debian, Maven or NPM repository.
    """
    package = models.ForeignKey(Package, on_delete=models.CASCADE)
    repository = models.CharField(
        max_length=100,
        help_text='Repository URL eg:http://central.maven.org',
        blank=True,
    )
    platform = models.CharField(
        max_length=50,
        help_text='Platform eg:maven',
        blank=True,
    )
    name = models.CharField(
        max_length=50,
        help_text='Package reference name eg:org.apache.commons.io',
        blank=True,
    )
    version = models.CharField(
        max_length=50,
        help_text='Reference version',
        blank=True,
    )

    def __str__(self):
        return self.platform
