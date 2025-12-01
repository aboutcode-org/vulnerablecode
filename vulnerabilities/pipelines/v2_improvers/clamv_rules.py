#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import gzip
import io
import os
import shutil
import tarfile
import tempfile
from pathlib import Path
from typing import List

import requests

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryDetectionRule
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import find_all_cve


def extract_cvd(cvd_path, output_dir):
    """
    Extract a CVD file. CVD format: 512-byte header + gzipped tar archive and returns Path to output directory
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    with open(cvd_path, "rb") as f:
        f.seek(512)  # Skip header
        compressed_data = f.read()

    decompressed_data = gzip.decompress(compressed_data)
    tar_buffer = io.BytesIO(decompressed_data)

    with tarfile.open(fileobj=tar_buffer, mode="r:") as tar:
        tar.extractall(path=output_path)

    for file in output_path.rglob("*"):
        if file.is_file():
            file.chmod(0o644)  # rw-r--r--
    return output_path


def parse_ndb_file(ndb_path: Path) -> List[dict]:
    """Parse a .ndb file (extended signatures). Return list of dicts."""
    signatures = []
    with ndb_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) >= 4:
                signatures.append(
                    {
                        "name": parts[0],
                        "target_type": parts[1],
                        "offset": parts[2],
                        "hex_signature": parts[3],
                        "line_num": line_num,
                    }
                )
    return signatures


def parse_hdb_file(hdb_path: Path) -> List[dict]:
    """Parse a .hdb file (MD5 hash signatures). Return list of dicts."""
    signatures = []
    with hdb_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) >= 3:
                signatures.append(
                    {
                        "hash": parts[0],
                        "file_size": parts[1],
                        "name": parts[2],
                        "line_num": line_num,
                    }
                )
    return signatures


def extract_cve_id(name: str):
    """Normalize underscores and extract the first CVE ID from a string, or None."""
    normalized = name.replace("_", "-")
    cves = [cve.upper() for cve in find_all_cve(normalized)]
    return cves[0] if cves else None


class ClamVRulesImproverPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Pipeline that downloads ClamAV database (main.cvd), extracts signatures,
    parses .ndb and .hdb files and save a detection rules.
    """

    pipeline_id = "clamv_rules"
    MAIN_DATABASE_URL = "https://database.clamav.net/main.cvd"
    license_url = ""
    license_expression = "GNU GENERAL PUBLIC LICENSE"

    @classmethod
    def steps(cls):
        return (
            cls.download_database,
            cls.extract_database,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def download_database(self):
        """Download ClamAV database using the supported API with proper headers."""

        self.log("Downloading ClamAV database…")
        self.db_dir = Path(tempfile.mkdtemp()) / "clamav_db"
        self.db_dir.mkdir(parents=True, exist_ok=True)

        database_url = "https://database.clamav.net/main.cvd?api-version=1"
        headers = {
            "User-Agent": "ClamAV-Client/1.0 (https://github.com/yourproject)",
            "Accept": "*/*",
        }

        filename = self.db_dir / "main.cvd"
        self.log(f"Downloading {database_url} → {filename}")

        resp = requests.get(database_url, headers=headers, stream=True, timeout=30)
        resp.raise_for_status()

        with filename.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        self.log("ClamAV DB file downloaded successfully.")

    def extract_database(self):
        """Extract the downloaded CVD into a directory"""
        out_dir = self.db_dir / "extracted"
        self.extract_cvd_dir = extract_cvd(self.db_dir / "main.cvd", out_dir)
        self.log(f"Extracted CVD to {self.extract_cvd_dir}")

    def collect_and_store_advisories(self):
        """Parse .ndb and .hdb files and store rules in the DB."""
        rules = {}
        for entry in parse_hdb_file(self.extract_cvd_dir / "main.hdb") + parse_ndb_file(
            self.extract_cvd_dir / "main.ndb"
        ):
            name = entry.get("name", "")
            cve = extract_cve_id(name)
            if cve:
                rules[cve] = entry

        rules_added = 0
        for cve_id, rule_text in rules.items():
            advisories = set()
            try:
                if alias := AdvisoryAlias.objects.get(alias=cve_id):
                    for adv in alias.advisories.all():
                        advisories.add(adv)
            except AdvisoryAlias.DoesNotExist:
                self.log(f"Advisory {cve_id} not found.")
                continue

            for advisory in advisories:
                AdvisoryDetectionRule.objects.update_or_create(
                    advisory=advisory,
                    rule_type="clamav",
                    defaults={
                        "rule_text": str(rule_text),
                    },
                )

                rules_added += 1
        self.log(f"Successfully added/updated {rules_added} rules for advisories.")

    def clean_downloads(self):
        """Clean up downloaded files."""
        if getattr(self, "db_dir", None) and os.path.exists(self.db_dir):
            shutil.rmtree(self.db_dir, ignore_errors=True)
            self.log("Cleaned up downloaded files.")

    def on_failure(self):
        """Ensure cleanup on failure."""
        self.clean_downloads()
