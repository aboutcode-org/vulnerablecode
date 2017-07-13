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

# Ubuntu test data
ubuntu_test_data = """
<tr class="High">
<td class="cve"><a href="CVE-2002-2439">CVE-2002-2439</a></td>
<td class="pkg"><a href="pkg/gcc-4.4.html">gcc-4.4</a></td>
<td class="needs-triage">needs-triage*</td>
<td class="needs-triage">needs-triage</td>
<td class="DNE">DNE</td>
<td class="DNE">DNE</td>
<td class="DNE">DNE</td>
<td class="DNE">DNE</td>
<td class="DNE">DNE</td>
<td style=""><a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-2439">Mitre</a>
<a href="https://launchpad.net/bugs/cve/CVE-2002-2439">LP</a>
<a href="http://security-tracker.debian.org/tracker/CVE-2002-2439">Debian</a></td></tr>
"""

# Debian test data
debian_test_data = """
<tr><td><a href="/tracker/source-package/389-ds-base">389-ds-base</a>
</td><td><a href="/tracker/CVE-2016-5416">CVE-2016-5416</a>
</td><td>not yet assigned</td><td>?</td></tr>
"""


def test_ubuntu_data():
    from scraper import ubuntu
    test_data = bs.BeautifulSoup(ubuntu_test_data, "lxml")
    extracted_data = ubuntu.extracted_data_ubuntu(test_data)

    assert extracted_data == (['CVE-2002-2439'],
                              ['High'],
                              ['gcc-4.4'])


def test_debian_data():
    from scraper import debian
    extracted_data = debian.extracted_data_debian(debian_test_data)

    assert extracted_data == (['CVE-2016-5416'],
                              ['389-ds-base'],
                              ['not yet assigned'])
