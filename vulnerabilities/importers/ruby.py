#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Optional

import requests
import saneyaml
from dateutil.parser import parse
from packageurl import PackageURL
from pytz import UTC
from univers.version_range import GemVersionRange
from univers.versions import RubygemsVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import build_description
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import load_yaml

logger = logging.getLogger(__name__)


class RubyImporter(Importer):
    license_url = "https://github.com/rubysec/ruby-advisory-db/blob/master/LICENSE.txt"
    repo_url = "git+https://github.com/rubysec/ruby-advisory-db"
    importer_name = "Ruby Importer"
    spdx_license_expression = "LicenseRef-scancode-public-domain-disclaimer"
    notice = """
    If you submit code or data to the ruby-advisory-db that is copyrighted by
    yourself, upon submission you hereby agree to release it into the public
    domain.

    The data imported from the ruby-advisory-db have been filtered to exclude 
    any non-public domain data from the data copyrighted by the Open 
    Source Vulnerability Database (http://osvdb.org).

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
    """

    def __init__(self, purl=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.purl = purl
        if self.purl and self.purl.type not in ("gem", "ruby"):
            print(
                f"Warning: PURL type {self.purl.type} is not 'gem' or 'ruby, may not match any advisories"
            )

    def advisory_data(self) -> Iterable[AdvisoryData]:
        if not self.purl:
            return self._batch_advisory_data()

        return self._package_first_advisory_data()

    def _package_first_advisory_data(self) -> Iterable[AdvisoryData]:
        if self.purl.type not in ("gem", "ruby"):
            return []

        try:
            yaml_files = []

            if self.purl.type == "gem":
                files = self._fetch_github_directory_content(f"gems/{self.purl.name}")
                yaml_files.extend(
                    [
                        (file, "gems")
                        for file in files
                        if file.endswith(".yml") and not file.startswith("OSVDB-")
                    ]
                )
            elif self.purl.type == "ruby":
                files = self._fetch_github_directory_content("rubies")
                yaml_files.extend(
                    [
                        (file, "rubies")
                        for file in files
                        if file.endswith(".yml") and not file.startswith("OSVDB-")
                    ]
                )

            for file_path, schema_type in yaml_files:
                content = self._fetch_github_file_content(file_path)
                if not content:
                    continue

                raw_data = saneyaml.load(content)

                if schema_type == "rubies" and raw_data.get("engine") != self.purl.name:
                    continue

                advisory_url = (
                    f"https://github.com/rubysec/ruby-advisory-db/blob/master/{file_path}"
                )
                advisory = parse_ruby_advisory(raw_data, schema_type, advisory_url)

                if advisory and self._advisory_affects_purl(advisory):
                    yield advisory

        except Exception as e:
            logger.error(f"Error fetching advisories for {self.purl}: {str(e)}")
            return []

    def _batch_advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone(self.repo_url)
            base_path = Path(self.vcs_response.dest_dir)
            supported_subdir = ["rubies", "gems"]
            for subdir in supported_subdir:
                for file_path in base_path.glob(f"{subdir}/**/*.yml"):
                    if file_path.name.startswith("OSVDB-"):
                        continue
                    raw_data = load_yaml(file_path)
                    advisory_url = get_advisory_url(
                        file=file_path,
                        base_path=base_path,
                        url="https://github.com/rubysec/ruby-advisory-db/blob/master/",
                    )
                    yield parse_ruby_advisory(raw_data, subdir, advisory_url)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def _advisory_affects_purl(self, advisory: AdvisoryData) -> bool:
        if not self.purl:
            return True

        for affected_package in advisory.affected_packages:
            if affected_package.package.type != self.purl.type:
                continue

            if affected_package.package.name != self.purl.name:
                continue

            if self.purl.version and affected_package.affected_version_range:
                purl_version = RubygemsVersion(self.purl.version)

                if purl_version not in affected_package.affected_version_range:
                    continue

            return True

        return False

    def _fetch_github_directory_content(self, path: str) -> List[str]:
        url = f"https://api.github.com/repos/rubysec/ruby-advisory-db/contents/{path}"
        response = requests.get(url)

        if response.status_code != 200:
            logger.error(f"Failed to fetch directory contents from GitHub: {response.status_code}")
            return []

        contents = response.json()
        file_paths = []

        for item in contents:
            if item["type"] == "file":
                file_paths.append(item["path"])
            elif item["type"] == "dir":
                file_paths.extend(self._fetch_github_directory_content(item["path"]))

        return file_paths

    def _fetch_github_file_content(self, path: str) -> Optional[str]:
        url = f"https://api.github.com/repos/rubysec/ruby-advisory-db/contents/{path}"
        response = requests.get(url, headers={"Accept": "application/vnd.github.v3.raw"})

        if response.status_code != 200:
            logger.error(f"Failed to fetch file content from GitHub: {response.status_code}")
            return None

        return response.text


def parse_ruby_advisory(record, schema_type, advisory_url):
    """
    Parse a ruby advisory file and return an AdvisoryData or None.
    Each advisory file contains the advisory information in YAML format.
    Schema: https://github.com/rubysec/ruby-advisory-db/tree/master/spec/schemas
    """
    if schema_type == "gems":
        package_name = record.get("gem")

        if not package_name:
            logger.error("Invalid package name")
        else:
            purl = PackageURL(type="gem", name=package_name)

            return AdvisoryData(
                aliases=get_aliases(record),
                summary=get_summary(record),
                affected_packages=get_affected_packages(record, purl),
                references=get_references(record),
                date_published=get_publish_time(record),
                url=advisory_url,
            )

    elif schema_type == "rubies":
        engine = record.get("engine")  # engine enum: [jruby, rbx, ruby]
        if not engine:
            logger.error("Invalid engine name")
        else:
            purl = PackageURL(type="ruby", name=engine)
            return AdvisoryData(
                aliases=get_aliases(record),
                summary=get_summary(record),
                affected_packages=get_affected_packages(record, purl),
                references=get_references(record),
                date_published=get_publish_time(record),
                url=advisory_url,
            )


def get_affected_packages(record, purl):
    """
    Return AffectedPackage objects one for each affected_version_range and invert the safe_version_ranges
    ( patched_versions , unaffected_versions ) then passing the purl and the inverted safe_version_range
    to the AffectedPackage object
    """
    safe_version_ranges = record.get("patched_versions", [])
    # this case happens when the advisory contain only 'patched_versions' field
    # and it has value None(i.e it is empty :( ).
    if not safe_version_ranges:
        safe_version_ranges = []
    safe_version_ranges += record.get("unaffected_versions", [])
    safe_version_ranges = [i for i in safe_version_ranges if i]

    affected_packages = []
    affected_version_ranges = [
        GemVersionRange.from_native(elem).invert() for elem in safe_version_ranges
    ]

    for affected_version_range in affected_version_ranges:
        affected_packages.append(
            AffectedPackage(
                package=purl,
                affected_version_range=affected_version_range,
            )
        )
    return affected_packages


def get_aliases(record) -> [str]:
    aliases = []
    if record.get("cve"):
        aliases.append("CVE-{}".format(record.get("cve")))
    if record.get("osvdb"):
        aliases.append("OSV-{}".format(record.get("osvdb")))
    if record.get("ghsa"):
        aliases.append("GHSA-{}".format(record.get("ghsa")))
    return aliases


def get_references(record) -> [Reference]:
    references = []
    cvss_v3 = record.get("cvss_v3")
    if record.get("url"):
        if not cvss_v3:
            references.append(Reference(url=record.get("url")))
        else:
            references.append(
                Reference(
                    url=record.get("url"),
                    severities=[
                        VulnerabilitySeverity(system=SCORING_SYSTEMS["cvssv3"], value=cvss_v3)
                    ],
                )
            )
    return references


def get_publish_time(record):
    date = record.get("date")
    if not date:
        return
    return parse(date).replace(tzinfo=UTC)


def get_summary(record):
    title = record.get("title") or ""
    description = record.get("description") or ""
    return build_description(summary=title, description=description)
