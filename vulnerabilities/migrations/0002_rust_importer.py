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

from django.db import migrations


def add_rust_importer(apps, _):
    Importer = apps.get_model('vulnerabilities', 'Importer')

    Importer.objects.create(
        name='rust',
        license='https://creativecommons.org/publicdomain/zero/1.0/',
        last_run=None,
        data_source='RustDataSource',
        data_source_cfg={
            'repository_url': 'https://github.com/RustSec/advisory-db',
        },
    )


def remove_rust_importer(apps, _):
    Importer = apps.get_model('vulnerabilities', 'Importer')
    qs = Importer.objects.filter(name='rust')
    if qs:
        qs[0].delete()


class Migration(migrations.Migration):

    dependencies = [
        ('vulnerabilities', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(add_rust_importer, remove_rust_importer),
    ]
