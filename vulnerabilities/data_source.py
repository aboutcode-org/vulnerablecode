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

from datetime import datetime
from typing import Any
from typing import ContextManager
from typing import Mapping
from typing import Optional
from typing import Sequence
import dataclasses

from packageurl import PackageURL


@dataclasses.dataclass
class DataSource(ContextManager):
    """
    This class defines how importers consume advisories from a data source.

    It makes a distinction between newly added records since the last run and modified records. This allows the import
    logic to pick appropriate database operations.
    """
    batch_size: int
    cutoff_date: Optional[datetime] = None
    config: Optional[Mapping[str, Any]] = dataclasses.field(default_factory=dict)

    def __enter__(self):
        """
        Subclasses acquire per-run resources, such as network connections, file downloads, etc. here.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Subclasses release per-run resources acquired in __enter__() here.
        """
        pass

    def added_advisories(self):
        """
        Subclasses yield batch_size sized batches of Advisory objects that have been added to the data source
        since self.cutoff_date.
        """
        raise StopIteration

    def updated_advisories(self):
        """
        Subclasses yield batch_size sized batches of Advisory objects that have been modified since
        self.cutoff_date.

        NOTE: Data sources that do not enable detection of changes to existing records vs added records must only
              implement this method, not new_records(). The ImportRunner relies on this contract to decide between
              insert and update operations.
        """
        raise StopIteration


@dataclasses.dataclass
class Advisory:
    """
    This data class expresses the contract between data sources and the import runner.
    Data sources are expected to be usable as context managers and generators, yielding batches of Advisory sequences.

    NB: There are two representations for package URLs that are commonly used by code consuming this data class;
        PackageURL objects and strings. As a convention, the former is referred to in variable names, etc. as
        "package_urls" and the latter as "purls".
    """
    summary: str
    impacted_package_urls: Sequence[PackageURL]
    resolved_package_urls: Sequence[PackageURL] = dataclasses.field(default_factory=list)
    references: Sequence[str] = dataclasses.field(default_factory=list)
    cve_id: Optional[str] = None

    @property
    def impacted_purls(self):
        return {str(p) for p in self.impacted_package_urls}

    @property
    def resolved_purls(self):
        return {str(p) for p in self.resolved_package_urls}
