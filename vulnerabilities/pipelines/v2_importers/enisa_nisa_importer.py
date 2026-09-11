#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path
from typing import Iterable

from fetchcode.vcs import fetch_via_vcs
import saneyaml

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import find_all_cve
from vulnerabilities.utils import get_advisory_url


class EnisaNisaImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Import ENISA NISA advisories with tolerant parsing.

    This parser is intentionally fault-tolerant: when version mapping is malformed,
    it still extracts CVE aliases and URL references.
    """

    pipeline_id = "enisa_nisa_importer_v2"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://www.enisa.europa.eu/"
    repo_url = "git+https://github.com/enisaeu/CNW"

    precedence = 200

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

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()

    def _iter_structured_files(self):
        base_directory = Path(self.vcs_response.dest_dir)
        for file_path in base_directory.rglob("*"):
            if not file_path.is_file():
                continue

            suffix = file_path.suffix.lower()
            if suffix not in (".json", ".yaml", ".yml"):
                continue

            yield file_path

    def _load_items(self, file_path: Path):
        text = file_path.read_text(encoding="utf-8", errors="replace")
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            data = json.loads(text)
        else:
            data = saneyaml.load(text)

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            for key in ("advisories", "vulnerabilities", "items", "data"):
                nested = data.get(key)
                if isinstance(nested, list):
                    return nested
            return [data]

        return []

    def advisories_count(self):
        count = 0
        for file_path in self._iter_structured_files():
            try:
                count += len(self._load_items(file_path))
            except Exception:
                continue
        return count

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        base_directory = Path(self.vcs_response.dest_dir)

        for file_path in self._iter_structured_files():
            try:
                items = self._load_items(file_path)
            except Exception as e:
                self.log(f"Failed to parse {file_path}: {e}")
                continue

            advisory_url = get_advisory_url(
                file=file_path,
                base_path=base_directory,
                url="https://github.com/enisaeu/CNW/blob/main/",
            )

            for item in items:
                advisory = parse_nisa_advisory(item=item, advisory_url=advisory_url)
                if advisory:
                    yield advisory


def parse_nisa_advisory(item: dict, advisory_url: str):
    """
    Parse one NISA advisory item.

    This parser is intentionally simple and resilient. If package/version fields are
    malformed or unusable, we still emit an advisory with CVEs and references.
    """
    if not isinstance(item, dict):
        return None

    advisory_id = str(item.get("id") or item.get("advisory_id") or item.get("name") or "").strip()

    summary = str(item.get("summary") or item.get("title") or item.get("description") or "").strip()

    aliases = []
    for field in ("cve", "cve_id", "cve_ids", "aliases"):
        value = item.get(field)
        if isinstance(value, str):
            aliases.extend(find_all_cve(value))
        elif isinstance(value, list):
            for entry in value:
                aliases.extend(find_all_cve(str(entry)))

    if isinstance(item.get("description"), str):
        aliases.extend(find_all_cve(item.get("description")))

    aliases = list(dict.fromkeys([a for a in aliases if a]))

    if not advisory_id and aliases:
        advisory_id = aliases[0]

    if not advisory_id:
        return None

    reference_urls = []
    refs = item.get("references")

    if isinstance(refs, list):
        for ref in refs:
            if isinstance(ref, str):
                reference_urls.append(ref)
            elif isinstance(ref, dict):
                for key in ("url", "link", "href"):
                    if ref.get(key):
                        reference_urls.append(str(ref.get(key)))
                        break

    if item.get("url"):
        reference_urls.append(str(item.get("url")))

    reference_urls.append(advisory_url)

    references = []
    for url in list(dict.fromkeys([u.strip() for u in reference_urls if str(u).strip()])):
        references.append(ReferenceV2(url=url))

    return AdvisoryDataV2(
        advisory_id=advisory_id,
        aliases=[alias for alias in aliases if alias != advisory_id],
        summary=summary or advisory_id,
        affected_packages=[],
        references=references,
        url=advisory_url,
        original_advisory_text=json.dumps(item, indent=2, ensure_ascii=False),
    )
