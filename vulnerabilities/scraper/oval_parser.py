import xml.etree.ElementTree as ET
from dephell_specifier import RangeSpecifier

from vulnerabilities.scraper.lib_oval import (
    OvalDefinition, OvalDocument, OvalTest, OvalObject, OvalState)
from typing import List
from typing import Dict
from typing import Tuple
from typing import Set


class OvalExtractor:

    def __init__(self, translations: Dict, oval_document: ET.ElementTree):
        """
        oval_document = it is an Etree parsed xml document
        """
        self.translations = translations
        self.oval_document = OvalDocument(oval_document)
        self.all_definitions = self.oval_document.getDefinitions()
        self.all_tests = self.oval_document.getTests()

    def get_data(self) -> List[Dict]:
        """
        Returns  a list of dictionaries
        """
        oval_data = []
        for definition in self.all_definitions:

            definition_data = {'test_data': []}
            definition_data['description'] = definition.getMetadata(
            ).getDescription()
            definition_data['vuln_id'] = self.get_vuln_id_from_definition(
                definition)
            matching_tests = self.get_tests_of_definition(definition)
            if not matching_tests:
                continue
            for test in matching_tests:
                test_obj, test_state = self.get_object_state_of_test(test)
                if not test_obj or not test_state:
                    continue
                test_data = {'package_list': []}
                test_data['package_list'].extend(
                    self.get_pkgs_from_obj(test_obj))
                test_data['version_ranges'] = self.get_versionsrngs_from_state(
                    test_state)
                definition_data['test_data'].append(test_data)
            oval_data.append(definition_data)

        return oval_data

    def get_tests_of_definition(self, definition: OvalDefinition) -> List[OvalTest]:
        """
        returns a list of all valid tests of the passed definition
        """
        pass

    def get_object_state_of_test(self, test: OvalTest) -> Tuple[OvalObject, OvalState]:
        """
        returns a tuple of (OvalObject,OvalState) of an OvalTest
        """
        pass

    def get_pkgs_from_obj(self, obj: OvalObject) -> List[str]:
        """
        returns a list of all related packages
        """
        pass

    def get_versionsrngs_from_state(self, state: OvalState) -> RangeSpecifier:
        """
        returns a list of all related version ranges
        """
        pass

    @staticmethod
    def get_urls_from_definition(definition: OvalDefinition) -> Set[str]:
        pass

    @staticmethod
    def get_vuln_id_from_definition(definition):

        for child in definition.element.iter():
            if child.get('ref_id'):
                return child.get('ref_id')


class UbuntuOvalParser(OvalExtractor):

    def get_tests_of_definition(self, definition: OvalDefinition) -> List[OvalTest]:

        criteria_refs = []

        for child in definition.element.iter():

            if 'test_ref' in child.attrib:
                criteria_refs.append(child.get('test_ref'))

        # FIXME  complexity of this can be reduced to O(1) by using a dictionary which maps
        # oval_ids to their element. A simple imporvement could be instead of iterating over all
        # tests, we could simply use OvalDocument.getElementById method
        matching_tests = []
        for test in self.all_tests:
            for ref in criteria_refs:
                if test.getId() == ref and len(test.element) == 2:
                    matching_tests.append(test)

        return matching_tests

    def get_object_state_of_test(self, test: OvalTest) -> Tuple[OvalObject, OvalState]:

        obj, state = list(test.element)[0].get(
            'object_ref'), list(test.element)[1].get('state_ref')
        obj = self.oval_document.getElementByID(obj)
        state = self.oval_document.getElementByID(state)

        return (obj, state)

    def get_pkgs_from_obj(self, obj: OvalObject) -> List[str]:

        pkg_list = []

        for var in obj.element:
            if var.get('var_ref'):
                var_elem = self.oval_document.getElementByID(
                    var.get('var_ref'))
                for vals in var_elem.element:
                    pkg_list.append(vals.text)
            else:
                pkg_list.append(var.text)

        return pkg_list

    def get_versionsrngs_from_state(self, state: OvalState) -> RangeSpecifier:

        for var in state.element:
            if var.get('operation'):

                operand = self.translations[var.get('operation')]
                version = var.text
                version_range = operand + version
                return RangeSpecifier(version_range)

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
                break

        return all_urls
