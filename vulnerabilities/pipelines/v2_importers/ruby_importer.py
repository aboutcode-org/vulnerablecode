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

from dateutil.parser import parse
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from pytz import UTC
from univers.version_range import GemVersionRange

from vulnerabilities.importer import AdvisoryData, AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import CVSSV2
from vulnerabilities.severity_systems import CVSSV3
from vulnerabilities.severity_systems import CVSSV4
from vulnerabilities.utils import build_description
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import load_yaml

logger = logging.getLogger(__name__)


class RubyImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    license_url = "https://github.com/rubysec/ruby-advisory-db/blob/master/LICENSE.txt"
    repo_url = "git+https://github.com/rubysec/ruby-advisory-db"
    importer_name = "Ruby Importer"
    pipeline_id = "ruby_importer_v2"
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

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        return 10

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_path = Path(self.vcs_response.dest_dir)
        supported_subdir = ["rubies", "gems"]
        for subdir in supported_subdir:
            for file_path in base_path.glob(f"{subdir}/**/*.yml"):
                if file_path.name.startswith("OSVDB-"):
                    continue

                raw_data = load_yaml(file_path)
                advisory_id = file_path.stem
                advisory_url = get_advisory_url(
                    file=file_path,
                    base_path=base_path,
                    url="https://github.com/rubysec/ruby-advisory-db/blob/master/",
                )
                yield parse_ruby_advisory(advisory_id, raw_data, subdir, advisory_url)

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def parse_ruby_advisory(advisory_id, record, schema_type, advisory_url):
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
                advisory_id=advisory_id,
                aliases=get_aliases(record),
                summary=get_summary(record),
                affected_packages=get_affected_packages(record, purl),
                references=get_references(record),
                severities=get_severities(record),
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
                advisory_id=advisory_id,
                aliases=get_aliases(record),
                summary=get_summary(record),
                affected_packages=get_affected_packages(record, purl),
                severities=get_severities(record),
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
            AffectedPackageV2(
                package=purl,
                affected_version_range=affected_version_range,
                fixed_version_range=None
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


def get_references(record) -> [ReferenceV2]:
    references = []
    if record.get("url"):
        references.append(
            ReferenceV2(
                url=record.get("url"),
            )
        )
    return references


def get_severities(record):
    """
    Extract CVSS severity and return a list of VulnerabilitySeverity objects
    """

    severities = []
    cvss_v4 = record.get("cvss_v4")
    if cvss_v4:
        severities.append(
            VulnerabilitySeverity(system=CVSSV4, value=cvss_v4),
        )

    cvss_v3 = record.get("cvss_v3")
    if cvss_v3:
        severities.append(VulnerabilitySeverity(system=CVSSV3, value=cvss_v4))

    cvss_v2 = record.get("cvss_v2")
    if cvss_v2:
        severities.append(VulnerabilitySeverity(system=CVSSV2, value=cvss_v2))

    return severities


def get_publish_time(record):
    date = record.get("date")
    if not date:
        return
    return parse(date).replace(tzinfo=UTC)


def get_summary(record):
    title = record.get("title") or ""
    description = record.get("description") or ""
    return build_description(summary=title, description=description)
