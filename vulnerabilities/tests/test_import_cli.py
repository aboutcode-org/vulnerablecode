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

from io import StringIO

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase


class ImportCommandTest(TestCase):
    def test_list_sources(self):
        buf = StringIO()
        
        call_command('import', '--list', stdout=buf)
        
        out = buf.getvalue()
        self.assertIn('debian', out)
        self.assertIn('ubuntu', out)
        self.assertIn('archlinux', out)

    def test_missing_sources(self):
        with self.assertRaises(CommandError) as cm: 
           call_command('import', stdout=StringIO())

        err = str(cm.exception)
        self.assertIn('Please provide at least one data source', err)

    def test_unknown_sources(self):
        with self.assertRaises(CommandError) as cm:
            call_command('import', 'debian', 'foo', 'bar', stdout=StringIO())

        err = str(cm.exception)
        self.assertIn('bar', err)
        self.assertIn('foo', err)
        self.assertNotIn('debian', err)
