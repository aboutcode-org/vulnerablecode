import os
import pathlib
from unittest.mock import patch
from unittest import TestCase
from collections import OrderedDict

from packageurl import PackageURL

from vulnerabilities.importers.ruby import rubyDataSource
from vulnerabilities.data_source import GitDataSourceConfiguration
from vulnerabilities.data_source import Advisory


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, 'test_data', 'ruby')

MOCK_ADDED_FILES = []

for filepath in pathlib.Path(TEST_DATA).glob('**/*.yml'):
    MOCK_ADDED_FILES.append(filepath.absolute())


class rubyDataSourceTest(TestCase):

    @classmethod
    def setUpClass(cls):
        data_source_cfg = {
            'repository_url': 'https://github.com/rubysec/ruby-advisory-db.git', }
        cls.data_src = rubyDataSource(1, config=data_source_cfg)

    @patch('vulnerabilities.importers.ruby.rubyAPI.get_all_version_of_package',
           return_value={'1.0.0', '1.8.0', '2.0.3'})
    def test_process_file(self, mock_write):
        expected_advisories = {
            Advisory(
                summary=('An issue was discovered in'
                         ' rack-protection/lib/rack/protection/path_traversal.rb\n'
                         'in Sinatra 2.x before 2.0.1 on Windows.'
                         ' Path traversal is possible via backslash\ncharacters.\n'),
                impacted_package_urls={
                    PackageURL(
                        type='gem',
                        namespace=None,
                        name='sinatra',
                        version='1.8.0',
                        qualifiers=OrderedDict(),
                        subpath=None)},
                resolved_package_urls={
                    PackageURL(
                        type='gem',
                        namespace=None,
                        name='sinatra',
                        version='1.0.0',
                        qualifiers=OrderedDict(),
                        subpath=None),
                    PackageURL(
                        type='gem',
                        namespace=None,
                        name='sinatra',
                        version='2.0.3',
                        qualifiers=OrderedDict(),
                        subpath=None)},
                reference_urls='https://github.com/sinatra/sinatra/pull/1379',
                reference_ids=[],
                cve_id='CVE-2018-7212'),
            Advisory(
                summary=('Sinatra before 2.0.2 has XSS via the 400 Bad Request '
                         'page that occurs upon a params parser exception.\n'),
                impacted_package_urls={
                    PackageURL(
                        type='gem',
                        namespace=None,
                        name='sinatra',
                        version='1.0.0',
                        qualifiers=OrderedDict(),
                        subpath=None),
                    PackageURL(
                        type='gem',
                        namespace=None,
                        name='sinatra',
                        version='1.8.0',
                        qualifiers=OrderedDict(),
                        subpath=None)},
                resolved_package_urls={
                    PackageURL(
                        type='gem',
                        namespace=None,
                        name='sinatra',
                        version='2.0.3',
                        qualifiers=OrderedDict(),
                        subpath=None)},
                reference_urls='https://github.com/sinatra/sinatra/issues/1428',
                reference_ids=[],
                cve_id='CVE-2018-11627'),
            None}

        found_advisories = set()

        for p in MOCK_ADDED_FILES:
            found_advisories.add(self.data_src._process_file(p))
        assert found_advisories == expected_advisories

    def test_categorize_versions(self):

        all_versions = {'1.0.0', '1.2.0', '9.0.2', '0.2.3'}
        safe_ver_ranges = ['==1.0.0', '>1.2.0']

        exp_safe_vers = {'1.0.0', '9.0.2'}
        exp_aff_vers = {'1.2.0', '0.2.3'}

        safe_vers, aff_vers = self.data_src.categorize_versions(
            all_versions, safe_ver_ranges)
        assert exp_aff_vers == aff_vers
        assert exp_safe_vers == safe_vers
