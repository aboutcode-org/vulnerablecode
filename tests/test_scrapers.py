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

from scraper import ubuntu
from scraper import debian


def test_ubuntu_extract_cves():
    test_input = """
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
        <td style="">
            <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-2439">Mitre</a>
            <a href="https://launchpad.net/bugs/cve/CVE-2002-2439">LP</a>
            <a href="http://security-tracker.debian.org/tracker/CVE-2002-2439">Debian</a>
        </td>
    </tr>
    """

    expected = (
        [{'cve_id': 'CVE-2002-2439',
          'package_name': 'gcc-4.4',
          'vulnerability_status': 'High'}]
    )

    assert expected == ubuntu.extract_cves(test_input)


def test_debian_extract_tracker_paths():
    test_input = """
    <ul>
        <li><a href="/tracker/status/release/unstable">Vulnerable packages in the unstable suite</a></li>
        <li><a href="/tracker/status/release/testing">Vulnerable packages in the testing suite</a></li>
        <li><a href="/tracker/status/release/stable">Vulnerable packages in the stable suite</a></li>
        <li><a href="/tracker/status/release/stable-backports">Vulnerable packages in backports for stable</a></li>
        <li><a href="/tracker/status/release/oldstable">Vulnerable packages in the oldstable suite</a></li>
        <li><a href="/tracker/status/release/oldstable-backports">Vulnerable packages in backports for oldstable</a></li>
        <li><a href="/tracker/status/release/oldoldstable">Vulnerable packages in the oldoldstable suite</a></li>
        <li><a href="/tracker/status/release/oldoldstable-backports">Vulnerable packages in backports for oldoldstable</a></li>
        <li><a href="/tracker/status/dtsa-candidates">Candidates for DTSAs</a></li>
        <li><a href="/tracker/status/todo">TODO items</a></li>
        <li><a href="/tracker/status/undetermined">Packages that may be vulnerable but need to be checked (undetermined issues)</a></li>
        <li><a href="/tracker/status/unimportant">Packages that have open unimportant issues</a></li>
        <li><a href="/tracker/status/itp">ITPs with potential security issues</a></li>
        <li><a href="/tracker/status/unreported">Open vulnerabilities without filed Debian bugs</a></li>
        <li><a href="/tracker/data/unknown-packages">Packages names not found in the archive</a></li>
        <li><a href="/tracker/data/fake-names">Tracked issues without a CVE name</a></li>
        <li><a href="/tracker/data/missing-epochs">Package versions which might lack an epoch</a></li>
        <li><a href="/tracker/data/latently-vulnerable">Packages which are latently vulnerable in unstable</a></li>
        <li><a href="/tracker/data/funny-versions">Packages with strange version numbers</a></li>
        <li><a href="/tracker/data/releases">Covered Debian releases and architectures</a></li>
        <li><a href="/tracker/data/json">All information in JSON format</a></li>
    </ul>
    """

    expected = [
        '/tracker/status/release/unstable',
        '/tracker/status/release/testing',
        '/tracker/status/release/stable',
        '/tracker/status/release/stable-backports',
        '/tracker/status/release/oldstable',
        '/tracker/status/release/oldstable-backports',
        '/tracker/status/release/oldoldstable',
        '/tracker/status/release/oldoldstable-backports',
        '/tracker/status/dtsa-candidates',
        '/tracker/status/todo',
        '/tracker/status/undetermined',
        '/tracker/status/unimportant',
        '/tracker/status/itp',
        '/tracker/status/unreported',
        '/tracker/data/unknown-packages',
        '/tracker/data/fake-names',
        '/tracker/data/missing-epochs',
        '/tracker/data/latently-vulnerable',
        '/tracker/data/funny-versions',
        '/tracker/data/releases',
        '/tracker/data/json',
    ]

    assert expected == debian.extract_tracker_paths(test_input)


def test_debian_extract_cves_from_tracker():
    test_input = """
    <tr>
        <td><a href="/tracker/source-package/389-ds-base">389-ds-base</a></td>
        <td><a href="/tracker/CVE-2016-5416">CVE-2016-5416</a></td>
        <td>not yet assigned</td><td>?</td>
    </tr>
    """

    expected = (
        [{'cve_id': 'CVE-2016-5416',
          'package_name': '389-ds-base',
          'vulnerability_status': 'not yet assigned'}]
    )

    assert expected == debian.extract_cves_from_tracker(test_input)
