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

from urllib.request import urlopen
import json

DEBIAN_ROOT_URL = "https://security-tracker.debian.org/tracker/data/json"


def json_data():
    """
    Return JSON of Debian vulnerability data.
    """
    debian_data = urlopen(DEBIAN_ROOT_URL).read()
    json_data = json.loads(debian_data)

    return json_data


def extract_data(data):
    """
    Return a dictionary of package names and vulnerability details.
    Accepts `JSON` as input.
    """
    final_data = []

    for package_name, vulnerabilities in data.items():
        for vulnerability, details in vulnerabilities.items():
            for distro, version_detail in details.get('releases', {}).items():
                if distro == 'jessie':
                    final_data.append({
                        "package_name": package_name,
                        "vulnerability_id": vulnerability,
                        "status": version_detail.get('status'),
                        "Urgency": version_detail.get("urgency"),
                        "Fixed_Version": version_detail.get("fixed_version")
                            }
                        )

    return final_data
