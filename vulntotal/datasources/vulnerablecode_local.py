#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import os
from typing import Optional
from urllib.parse import urljoin

import requests
from dotenv import load_dotenv
from packageurl import PackageURL

from vulntotal.datasources.vulnerablecode import VulnerableCodeDataSource
from vulntotal.validator import VendorData

logger = logging.getLogger(__name__)


def _is_true(val: Optional[str]) -> bool:
    return (val is not None) and str(val).strip().lower() in {"1", "true", "yes", "on"}


class LocalVulnerableCodeDataSource(VulnerableCodeDataSource):
    live_eval_api_path = "api/v2/live-evaluation/evaluate"
    vc_purl_search_api_path = "api/v2/advisories-packages/bulk_search/"

    def __init__(self):
        super().__init__()
        load_dotenv()

        host = os.environ.get("VCIO_HOST", "localhost").rstrip("/")
        port = os.environ.get("VCIO_PORT", "8000")

        if host.startswith("http://") or host.startswith("https://"):
            base = host
        else:
            base = f"http://{host}:{port}"

        self.global_instance = f"{base}/"

        self._enable_live_eval = _is_true(os.environ.get("ENABLE_LIVE_EVAL", False))

    def _trigger_live_evaluation(self, purl: PackageURL) -> bool:
        """Trigger live evaluation for the given purl on the local VCIO instance.

        Returns True if the trigger was accepted and False otherwise.
        """
        url = urljoin(self.global_instance, self.live_eval_api_path)
        try:
            response = requests.post(url, json={"purl_string": str(purl)})
        except Exception as e:
            logger.error(f"Live evaluation trigger failed for {purl}: {e}")
            return False

        if response.status_code != 202:
            logger.error(
                f"Live evaluation trigger for {purl} failed with status {response.status_code}: {response.text}"
            )
            return False

        logger.info(f"Live evaluation accepted for {purl} on {url}")
        return True

    def fetch_post_json(self, payload):
        url = urljoin(self.global_instance, self.vc_purl_search_api_path)
        try:
            response = requests.post(url, json=payload)
        except Exception as e:
            logger.error(f"Error while fetching {url}: {e}")
            return
        if response.status_code != 200:
            logger.error(f"Error while fetching {url}")
            return
        return response.json()

    def datasource_advisory(self, purl):
        if purl.type not in self.supported_ecosystem() or purl.version is None:
            return

        if self._enable_live_eval:
            self._trigger_live_evaluation(purl)

        metadata = self.fetch_post_json({"purls": [str(purl)]})
        self._raw_dump.append(metadata)
        if not metadata:
            return

        packages = metadata.get("packages") or []
        advisories_map = metadata.get("advisories") or {}
        if not packages:
            return

        pkg_entry = next((pkg for pkg in packages if pkg.get("purl") == str(purl)), packages[0])
        affected_map = pkg_entry.get("affected_by_vulnerabilities", {}) or {}

        for advisory_id, details in affected_map.items():
            fixed_versions = []
            fixed_purls = details.get("fixed_by_packages") or []
            for fp in fixed_purls:
                try:
                    ver = PackageURL.from_string(fp).version
                    if ver:
                        fixed_versions.append(ver)
                except Exception:
                    continue

            advisory_key = advisory_id.split("/")[-1]
            advisory_obj = advisories_map.get(advisory_key, {})
            aliases = advisory_obj.get("aliases") or []

            yield VendorData(
                purl=PackageURL(purl.type, purl.namespace, purl.name),
                aliases=aliases,
                affected_versions=[purl.version],
                fixed_versions=fixed_versions,
            )
