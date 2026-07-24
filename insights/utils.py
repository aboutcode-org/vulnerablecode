#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from vulnerabilities.models import Weakness


def get_cwe_label(cwe_id: str) -> str:
    num = str(cwe_id).replace("CWE-", "")

    try:
        name = Weakness().get_cwe(num).name
        return f"CWE-{num} · {name}" if name else f"CWE-{num}"
    except KeyError:
        return f"CWE-{num}"


def format_importer_name(name: str) -> str:
    """
    Format importer internal names into human-readable labels.
    e.g., 'pysec_importer_v2' -> 'Pysec Importer'
    """
    parts = name.rsplit("_v", 1)
    if len(parts) == 2 and parts[1].isdigit():
        name = parts[0]
    return name.replace("_", " ")
