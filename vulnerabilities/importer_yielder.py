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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import os
import json

from vulnerabilities.models import Importer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class ImporterYielder:

    def __init__(self):
        self.load_registry()

    def load_registry(self):
        registry_path = os.path.join(BASE_DIR, 'importer_registry.json')

        with open(registry_path) as f:
            self.registry = json.load(f)

    def get_importers(self):
        all_importers = []

        for importer in self.registry:
            imp, created = Importer.objects.get_or_create(
                name=importer['name'],
                data_source=importer['data_source'],
                license=importer['license'])

            if created:
                # Sets the dynamic fields equal to the default values
                imp.data_source_cfg = importer['data_source_cfg']
                imp.last_run = importer['last_run']
                imp.save()

            all_importers.append(imp)

        return all_importers
