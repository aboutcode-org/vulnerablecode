import os
import unittest
import xml.etree.ElementTree as ET

from dephell_specifier import RangeSpecifier


from vulnerabilities.importers.oval_parser import OvalParser


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


class TestSUSEOvalParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        xml_doc = ET.parse(os.path.join(TEST_DATA, "suse_oval_data.xml"))
        translator = {"less than": "<"}
        #  all the elements which require "equals" are ignored(because they are not useful) 
        cls.parsed_oval = OvalParser(translator, xml_doc)

    def setUp(self):
        self.definition_1 = self.parsed_oval.all_definitions[0]
        self.definition_2 = self.parsed_oval.all_definitions[1]

    def test_get_definitions(self):

        assert len(self.parsed_oval.all_definitions) == 2
        assert (
            self.parsed_oval.all_definitions[0].getId()
            == "oval:org.opensuse.security:def:20094112"
        )
        assert (
            self.parsed_oval.all_definitions[1].getId()
            == "oval:org.opensuse.security:def:20112767"
        )

    def test_get_tests_of_definition(self):

        definition_1_test_ids = {"oval:org.opensuse.security:tst:2009281999",
                                 "oval:org.opensuse.security:tst:2009282000",
                                }
        definition_2_test_ids = {'oval:org.opensuse.security:tst:2009271113',
                                 'oval:org.opensuse.security:tst:2009271114',
                                }

        assert definition_1_test_ids ==  {i.getId() for i in self.parsed_oval.get_tests_of_definition(self.definition_1)}

        assert definition_2_test_ids ==  {i.getId() for i in self.parsed_oval.get_tests_of_definition(self.definition_2)}
            
    def test_get_vuln_id_from_definition(self):

        vuln_id_1 = "CVE-2009-4112"
        vuln_id_2 = "CVE-2011-2767"

        assert vuln_id_1 == self.parsed_oval.get_vuln_id_from_definition(
            self.definition_1
        )
        assert vuln_id_2 == self.parsed_oval.get_vuln_id_from_definition(
            self.definition_2
        )

    def test_get_object_state_of_test(self):

        # This method is inherited as it is from UbuntuOvalParser
        # this test ensures that the method works with suse OVAL documents

        assert len(self.parsed_oval.oval_document.getTests()) == 9

        test_1 = self.parsed_oval.oval_document.getTests()[0]
        test_2 = self.parsed_oval.oval_document.getTests()[1]

        obj_t1, state_t1 = self.parsed_oval.get_object_state_of_test(test_1)
        obj_t2, state_t2 = self.parsed_oval.get_object_state_of_test(test_2)

        assert state_t1.getId() == "oval:org.opensuse.security:ste:2009068342"
        assert state_t2.getId() == "oval:org.opensuse.security:ste:2009072069"

        assert obj_t2.getId() == "oval:org.opensuse.security:obj:2009031297"
        assert obj_t1.getId() == "oval:org.opensuse.security:obj:2009031246"

    def test_get_pkgs_from_obj(self):

        assert len(self.parsed_oval.oval_document.getObjects()) == 5

        obj_t1 = self.parsed_oval.oval_document.getObjects()[0]
        obj_t2 = self.parsed_oval.oval_document.getObjects()[1]
       
        pkg_set1 = set(self.parsed_oval.get_pkgs_from_obj(obj_t1))
        pkg_set2 = set(self.parsed_oval.get_pkgs_from_obj(obj_t2))

        assert pkg_set1 == {'openSUSE-release'}
        #In a full run we wont get pkg_set1 because we won't obtain 
        #it's object due to filters to  avoid such tests in  the first place 
        assert pkg_set2 == {'cacti'}


    def test_get_versionsrngs_from_state(self):

        assert len(self.parsed_oval.oval_document.getStates()) == 4

        state_1 = self.parsed_oval.oval_document.getStates()[0]
        state_2 = self.parsed_oval.oval_document.getStates()[1]

        exp_range_1 = None
        exp_range_2 = RangeSpecifier("<0:1.2.11-lp151.3.6")
        #In a full run we wont get exp_range1 because we won't obtain 
        #it's state due to filters to  avoid such tests in  the first place
        assert self.parsed_oval.get_versionsrngs_from_state(state_1) == exp_range_1
        assert self.parsed_oval.get_versionsrngs_from_state(state_2) == exp_range_2
    
    def test_get_urls_from_definition(self):

        def1_urls = {"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-4112",
                     "https://www.suse.com/security/cve/CVE-2009-4112.html",
                     "https://bugzilla.suse.com/1122535",
                     "https://bugzilla.suse.com/558664"
                    }

        assert def1_urls == self.parsed_oval.get_urls_from_definition(self.definition_1)            

        def2_urls = {"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2767",
                     "https://bugzilla.suse.com/1156944",
                     "https://www.suse.com/security/cve/CVE-2011-2767.html",
                    }

        assert def2_urls == self.parsed_oval.get_urls_from_definition(self.definition_2)       

    def test_get_data(self):

        expected_data = [
          {
            'test_data':
            [
                {
                'package_list': ['cacti'],
                'version_ranges': RangeSpecifier("<0:1.2.11-lp151.3.6")
                }
                ,
                {
                'package_list': ['cacti-spine'],
                'version_ranges': RangeSpecifier("<0:1.2.11-lp151.3.6")
                }
           ],
        'description':'\n        Cacti 0.8.7e and earlier allows remote authenticated administrators to gain privileges by modifying the "Data Input Method" for the "Linux - Get Memory Usage" setting to contain arbitrary commands.\n        ',
        'vuln_id': 'CVE-2009-4112',
        'reference_urls': {
            'https://bugzilla.suse.com/1122535',
            'https://bugzilla.suse.com/558664',
            'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-4112',
            'https://www.suse.com/security/cve/CVE-2009-4112.html'}
        },
          { 'test_data':
            [
                {
                'package_list': ['apache2-mod_perl'],
                'version_ranges': RangeSpecifier("<0:2.0.11-lp151.3.3")
                },
                {
                'package_list': ['apache2-mod_perl-devel'],
                'version_ranges': RangeSpecifier("<0:2.0.11-lp151.3.3")}
                ],
            'description': "\n        mod_perl 2.0 through 2.0.10 allows attackers to execute arbitrary Perl code by placing it in a user-owned .htaccess file, because (contrary to the documentation) there is no configuration option that permits Perl code for the administrator's control of HTTP request processing without also permitting unprivileged users to run Perl code in the context of the user account that runs Apache HTTP Server processes.\n        ",
            'vuln_id': 'CVE-2011-2767',
            'reference_urls': {
                'https://bugzilla.suse.com/1156944',
                'https://www.suse.com/security/cve/CVE-2011-2767.html',
                'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2767'
                            }
         }

         ]

        

        assert expected_data == self.parsed_oval.get_data()
    
