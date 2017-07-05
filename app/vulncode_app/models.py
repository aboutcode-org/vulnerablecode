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

from __future__ import unicode_literals
from django.db import models


class Vulnerability(models.Model):
	vulnerability_id = models.AutoField(primary_key=True)
	summary = models.TextField(max_length=50)
	cvss = models.FloatField(max_length=50)


class VulnerabilityReference(models.Model):
	vulnerability_id = models.ForeignKey('Vulnerability')
	source = models.CharField(max_length=50)
	reference_id = models.CharField(max_length=50)
	url = models.URLField(max_length=50)


class ImpactedPackage(models.Model):
	vulnerability_id = models.ForeignKey('Vulnerability')
	package_id = models.ForeignKey('Package')


class ResolvedPackage(models.Model):
	vulnerability_id = models.ForeignKey('Vulnerability')
	package_id = models.ForeignKey('Package')


class Package(models.Model):
	package_id = models.AutoField(primary_key=True)
	platform = models.CharField(max_length=50)
	name = models.CharField(max_length=50)
	version = models.FloatField(max_length=50)


class PackageReference(models.Model):
	package_id = models.ForeignKey('Package')
	repository = models.CharField(max_length=50)
	platform = models.CharField(max_length=50)
	name = models.CharField(max_length=50)
	version = models.FloatField(max_length=50)
