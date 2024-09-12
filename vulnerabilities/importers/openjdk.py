import urllib.parse as urlparse

import requests
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import GenericVersionRange
from univers.versions import GenericVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity


class OpenJDKImporter(Importer):
    root_url = "https://openjdk.org/groups/vulnerability/advisories/"
    license_url = "https://openjdk.org/legal/"
    spdx_license_expression = "CC-BY-4.0"
    importer_name = "OpenJDK Importer"

    def advisory_data(self):
        
        extracted_urls = []
        data_by_urls = {}

        #scraping the advisory urls
        data = requests.get(self.root_url).text
        soup = BeautifulSoup(data, features="lxml")
        li_tags = soup.find_all('li')
        li_contents = [li.get_text(strip=True) for li in li_tags]

        for link in li_contents:
            link = link.split()[0] #for getting only the year links
            link = '-'.join(link.split('/'))
            link = self.root_url + link
            extracted_urls.append(link)
            data_by_urls[link] = requests.get(link).text

        for url, data in data_by_urls.items():
            yield from to_advisories(data)



def to_advisories(data):
    soup_spec = BeautifulSoup(spec, features = "lxml")
    table_tags = soup_spec.find_all('table')
	#print(soup_spec.find_all('th'))

	#tables containing the vulnurability info of OpenJDK and OpenJFX

    #For OpenJDK vulnerability data
    try:
        OpenJDK_table = table_tags[0]
    
    except IndexError:
        pass

	
    OpenJDK_tr_tags = OpenJDK_table.select('tr')
	#print(OpenJDK_tr_tags)
    th_tags = OpenJDK_tr_tags[1].find_all('th')
    possible_affected_versions_OpenJDK = []

    for i in range(3, len(th_tags)):
	    possible_affected_versions_OpenJDK.append(th_tags[i].text)

    
    for i in range(2, len(OpenJDK_tr_tags)):
        td_tags = OpenJDK_tr_tags[i].select('td')
        affected_version_range = []
        try:
            cve_id, component, severity_score, *affected_ver = td_tags
            #print(severity_score.text)
            cve_id = cve_id.text
            component = ''.join(component.text.split('\n'))
            severity_score = severity_score.text.split('\n')[0]
            #print(f'{cve_id}, {component}, {severity_score}')
            
            for index, version in enumerate(possible_affected_versions_OpenJDK):
                if affected_ver[index].text:
                    affected_version_range.append(version)
            
            print(affected_version_range)
        
        except LookupError:
            pass


    #For OpenJFX vulnerability data
    try:
        OpenJFX_table = table_tags[1]
    
    except IndexError:
        pass