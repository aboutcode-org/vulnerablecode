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

import re
from typing import Optional
from typing import List
from typing import Dict
from typing import Tuple
from typing import Set
import xml.etree.ElementTree as ET

from dephell_specifier import RangeSpecifier

from vulnerabilities.lib_oval import OvalDefinition
from vulnerabilities.lib_oval import OvalDocument
from vulnerabilities.lib_oval import OvalObject
from vulnerabilities.lib_oval import OvalState
from vulnerabilities.lib_oval import OvalTest
import traceback


class OvalParser:

    def __init__(self, translations: Dict, oval_document: ET.ElementTree):

        self.translations = translations
        self.oval_document = OvalDocument(oval_document)
        self.all_definitions = self.oval_document.getDefinitions()
        self.all_tests = self.oval_document.getTests()

    def get_data(self) -> List[Dict]:
        """
        Return a list of OvalDefinition mappings.
        """
        oval_data = []
        for definition in self.all_definitions:

            matching_tests = self.get_tests_of_definition(definition)
            if not matching_tests:
                continue
            definition_data = {'test_data': []}
            # TODO:this could use some data cleaning
            definition_data['description'] = definition.getMetadata().getDescription() or ''

            definition_data['vuln_id'] = self.get_vuln_id_from_definition(definition)
            definition_data['reference_urls'] = self.get_urls_from_definition(definition)

            for test in matching_tests:
                test_obj, test_state = self.get_object_state_of_test(test)
                if not test_obj or not test_state:
                    continue
                test_data = {'package_list': []}
                test_data['package_list'].extend(self.get_pkgs_from_obj(test_obj))
                version_ranges = self.get_versionsrngs_from_state(test_state)
                test_data['version_ranges'] = version_ranges
                definition_data['test_data'].append(test_data)

            oval_data.append(definition_data)

        return oval_data

    def get_tests_of_definition(self, definition: OvalDefinition) -> List[OvalTest]:
        """
        returns a list of all valid tests of the passed OvalDefinition
        """

        criteria_refs = []

        for child in definition.element.iter():

            if 'test_ref' in child.attrib:
                criteria_refs.append(child.get('test_ref'))

        matching_tests = []
        for ref in criteria_refs:
            oval_test = self.oval_document.getElementByID(ref)
            if len(oval_test.element) == 2:
                _, state = self.get_object_state_of_test(oval_test)
                valid_test = True
                for child in state.element:
                    if child.get('operation') not in self.translations:
                        valid_test = False
                        break
                if valid_test:
                    matching_tests.append(
                        self.oval_document.getElementByID(ref))

        return matching_tests

    def get_object_state_of_test(self, test: OvalTest) -> Tuple[OvalObject, OvalState]:
        """
        returns a tuple of (OvalObject,OvalState) of an OvalTest
        """
        obj, state = list(test.element)[0].get(
            'object_ref'), list(test.element)[1].get('state_ref')
        obj = self.oval_document.getElementByID(obj)
        state = self.oval_document.getElementByID(state)
        return (obj, state)

    def get_pkgs_from_obj(self, obj: OvalObject) -> List[str]:
        """
        returns a list of all related packages nested within
        an OvalObject
        """

        pkg_list = []

        for var in obj.element:
            if var.get('var_ref'):
                var_elem = self.oval_document.getElementByID(
                    var.get('var_ref'))
                comment = var_elem.element.get('comment')
                pkg_name = re.match("'.+'", comment).group().replace("'", "")
                pkg_list.append(pkg_name)
            else:
                pkg_list.append(var.text)

        return pkg_list

    # TODO: this method needs a better name
    def get_versionsrngs_from_state(self, state: OvalState) -> Optional[RangeSpecifier]:
        """
        Return a version range(s)? from a state
        """
        for var in state.element:
            operation = var.get('operation')
            if not operation:
                continue
            operand = self.translations.get(operation) or ''
            if not operand:
                continue
            version = var.text or ''
            if not version:
                continue
            version_range = operand + version
            try:
                return RangeSpecifier(version_range)
            except Exception:
                # FIXME: we should not continue
                print(f"Failed to process invalid version_range in OvalState: {version_range}...continuing")

    @staticmethod
    def get_urls_from_definition(definition: OvalDefinition) -> Set[str]:
        all_urls = set()
        definition_metadata = definition.getMetadata().element
        for child in definition_metadata:
            if child.tag.endswith('reference'):
                all_urls.add(child.get('ref_url'))
            if child.tag.endswith('advisory'):
                for grandchild in child:
                    if grandchild.tag.endswith('ref'):
                        all_urls.add(grandchild.text)
                    if grandchild.get('href'):
                        all_urls.add(grandchild.get('href'))
                break

        return all_urls

    @staticmethod
    def get_vuln_id_from_definition(definition):
        # SUSE and Ubuntu OVAL files will get cves via this loop
        for child in definition.element.iter():
            if child.get('ref_id'):
                return child.get('ref_id')
        # Debian OVAL files will get cves via this
        return definition.getMetadata().getTitle()
