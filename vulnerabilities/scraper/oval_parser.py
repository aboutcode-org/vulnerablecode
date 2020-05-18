from typing import List
from typing import Dict
from typing import Tuple
from typing import Set
from typing import Optional
import xml.etree.ElementTree as ET

from dephell_specifier import RangeSpecifier

from vulnerabilities.scraper.lib_oval import (
    OvalDefinition, OvalDocument, OvalTest, OvalObject, OvalState, OvalElement)


class PerformantOvalDocument(OvalDocument):

    def __init__(self, tree):
        super().__init__(tree)
        self.id_to_definition = {
            el.getId(): el for el in self.getDefinitions()}
        self.id_to_test = {el.getId(): el for el in self.getTests()}
        self.id_to_object = {el.getId(): el for el in self.getObjects()}
        self.id_to_state = {el.getId(): el for el in self.getStates()}
        self.id_to_variable = {el.getId(): el for el in self.getVariables()}

    def getElementByID(self, oval_id: str) -> Optional[OvalElement]:
        if not oval_id:
            return None

        root = self.getDocumentRoot()
        if not root:
            return None
        try:
            oval_type = OvalElement.getElementTypeFromOvalID(oval_id)
        except Exception:
            return None

        if oval_type == OvalDefinition.DEFINITION:
            return self.id_to_definition[oval_id]
        elif oval_type == OvalDefinition.TEST:
            return self.id_to_test[oval_id]
        elif oval_type == OvalDefinition.OBJECT:
            return self.id_to_object[oval_id]
        elif oval_type == OvalDefinition.STATE:
            return self.id_to_state[oval_id]
        elif oval_type == OvalDefinition.VARIABLE:
            return self.id_to_variable[oval_id]
        else:
            return None


class OvalExtractor:

    def __init__(self, translations: Dict, oval_document: ET.ElementTree):

        self.translations = translations
        self.oval_document = PerformantOvalDocument(oval_document)
        self.all_definitions = self.oval_document.getDefinitions()
        self.all_tests = self.oval_document.getTests()

    def get_data(self) -> List[Dict]:
        """
        This is the orchestration method, it returns a list of dictionaries,
        where each dictionary represents data from an OvalDefinition
        """
        oval_data = []
        for definition in self.all_definitions:

            matching_tests = self.get_tests_of_definition(definition)
            if not matching_tests:
                continue
            definition_data = {'test_data': []}
            definition_data['description'] = definition.getMetadata(
            ).getDescription()
            definition_data['vuln_id'] = self.get_vuln_id_from_definition(
                definition)
            definition_data['reference_urls'] = self.get_urls_from_definition(
                definition
            )
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
        returns a list of all valid tests of the passed OvalDefinition
        """
        pass

    def get_object_state_of_test(self, test: OvalTest) -> Tuple[OvalObject, OvalState]:
        """
        returns a tuple of (OvalObject,OvalState) of an OvalTest
        """
        pass

    def get_pkgs_from_obj(self, obj: OvalObject) -> List[str]:
        """
        returns a list of all related packages nested within
        an OvalObject
        """
        pass

    def get_versionsrngs_from_state(self, state: OvalState) -> RangeSpecifier:
        """
        returns a list of all related version ranges within a
        state
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

        matching_tests = []
        for ref in criteria_refs:
            if len(self.oval_document.getElementByID(ref).element) == 2:
                matching_tests.append(self.oval_document.getElementByID(ref))

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
