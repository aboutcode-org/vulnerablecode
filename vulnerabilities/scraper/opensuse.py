import requests
from bs4 import BeautifulSoup

from vulnerabilities.scraper.cvrf_parser import cvrf_parser

base_url = 'http://ftp.suse.com/pub/projects/security/cvrf/'


def name_version_split(pkg_name):
    last_char = 0
    for i in range(len(pkg_name)):
        if pkg_name[i] == '-':
            if pkg_name[i + 1].isnumeric() and pkg_name[i - 1].isalpha():
                return (pkg_name[:i], pkg_name[i + 1:])


def get_urls_of_xmls_from_page(base_url):
    r = requests.get(base_url)
    soup = BeautifulSoup(r.content, 'lxml')
    for a_tag in soup.find_all('a', href=True):
        if a_tag['href'].endswith('.xml'):
            yield base_url + a_tag['href']


def import_vulnerabilities():
    vulnerabilities = []
    vulnerability_dicts = []
    for xml_url in get_urls_of_xmls_from_page(base_url):
        vulnerabilities = cvrf_parser.get_data_dict_from_url(xml_url)
        for vulnerability in vulnerabilities:
            description = vulnerability['Note_Notes'].split('lang:en|')[1]
            platform, package = vulnerability['ProductID'].split(':')
            if not name_version_split(package):
                continue
            pkg_name, pkg_version = name_version_split(package)
            cve_id = vulnerability['CVE_Vulnerability']
            ref_urls = vulnerability['URL_Reference']
            ref_ids = list(
                filter(lambda x: not x.startswith('CVE'),
                       vulnerability['Description_Reference'])
            )
            ref_ids = list(map(lambda x: x.replace(' ', '-').upper(), ref_ids))
            vulnerability_dicts.append(
                {
                    'description': description,
                    'platform': platform,
                    'vuln_id': cve_id,
                    'package_name': pkg_name,
                    'urls': ref_urls,
                    'ref_ids': ref_ids,
                    'version': pkg_version,
                }
            )

    return vulnerability_dicts
