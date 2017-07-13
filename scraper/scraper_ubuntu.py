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

import bs4 as bs 
import re
from urllib.request import urlopen


def ubuntu_data():
	cve_id = []
	package_name = []
	vulnerability_status = []
	
	url = urlopen("https://people.canonical.com/~ubuntu-security/cve/main.html")
	soup = bs.BeautifulSoup (url, "lxml")
	
	"""
	Scrape vulnerability status.
	Ubuntu provides a general vulnerability 
	status of a package across all it's releases. 
	"""
	for tag in soup.find_all('tr'):
		if re.match('<\w+\s\w+="(\w+)">', str(tag)):
			status = re.findall('<\w+\s\w+="(\w+)">', str(tag))
			vulnerability_status.append(status[0])

	for tag in soup.find_all('a'):
		href = tag.get ('href', None)

		if re.findall ('^CVE.+', href): 
			cve_id.append(href)
		
		if re.match('\pkg+.*', href):
			pkg = re.findall ('pkg/(.+)\.html', href)
			package_name.append(pkg[0])

	return cve_id, package_name, vulnerability_status
