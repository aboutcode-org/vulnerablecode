#
# Copyright (c) nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import datetime
import logging
from typing import Iterable
from typing import List

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.models import Advisory

logger = logging.getLogger(__name__)


class ImportRunner:
    """
    The ImportRunner is responsible for inserting and updating data about vulnerabilities and
    affected/unaffected/fixed packages in the database. The main goal for the implementation
    is correctness

    Correctness:
        - There must be no duplicates in the database (should be enforced by the schema).
        - No valid data from the data source must be skipped or truncated.
    """

    def __init__(self, importer_class: Importer):
        self.importer_class = importer_class

    def run(self) -> None:
        """
        Create a data source for the given importer and store the data retrieved in the database.
        """
        importer_name = self.importer_class.qualified_name
        importer_class = self.importer_class
        logger.info(f"Starting import for {importer_name}")
        advisory_datas = importer_class().advisory_data()
        count = process_advisories(advisory_datas=advisory_datas, importer_name=importer_name)
        logger.info(f"Finished import for {importer_name}. Imported {count} advisories.")


def process_advisories(advisory_datas: Iterable[AdvisoryData], importer_name: str) -> List:
    """
    Insert advisories into the database
    Return the number of inserted advisories.
    """
    count = 0
    for data in advisory_datas:
        # https://nvd.nist.gov/vuln/detail/CVE-2013-4314
        # https://github.com/cms-dev/cms/issues/888#issuecomment-516977572
        data.summary = data.summary.replace("\x00", "\uFFFD")
        obj, created = Advisory.objects.get_or_create(
            aliases=data.aliases,
            summary=data.summary,
            affected_packages=[pkg.to_dict() for pkg in data.affected_packages],
            references=[ref.to_dict() for ref in data.references],
            date_published=data.date_published,
            defaults={
                "created_by": importer_name,
                "date_collected": datetime.datetime.now(tz=datetime.timezone.utc),
            },
        )
        if created:
            logger.info(
                f"[*] New Advisory with aliases: {obj.aliases!r}, created_by: {obj.created_by}"
            )
            count += 1
        else:
            logger.debug(f"Advisory with aliases: {obj.aliases!r} already exists. Skipped.")

    return count
