#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from datetime import datetime
from unittest import mock
from unittest.mock import MagicMock

import pytest

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import DetectionRule
from vulnerabilities.pipelines.v2_improvers.sigma_rules import SigmaRulesImproverPipeline

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TEST_REPO_DIR = os.path.join(BASE_DIR, "../../test_data/sigma")


@pytest.mark.django_db
@mock.patch("vulnerabilities.pipelines.v2_improvers.sigma_rules.fetch_via_vcs")
def test_sigma_rules_db_improver(mock_fetch_via_vcs):
    mock_vcs = MagicMock()
    mock_vcs.dest_dir = TEST_REPO_DIR
    mock_vcs.delete = MagicMock()
    mock_fetch_via_vcs.return_value = mock_vcs

    adv1 = AdvisoryV2.objects.create(
        advisory_id="VCIO-123-0001",
        datasource_id="ds",
        avid="ds/VCIO-123-0001",
        unique_content_id="sgsdg45",
        url="https://test.com",
        date_collected=datetime.now(),
    )
    adv2 = AdvisoryV2.objects.create(
        advisory_id="VCIO-123-1002",
        datasource_id="ds",
        avid="ds/VCIO-123-1002",
        unique_content_id="6hd4d6f",
        url="https://test.com",
        date_collected=datetime.now(),
    )
    adv3 = AdvisoryV2.objects.create(
        advisory_id="VCIO-123-1003",
        datasource_id="ds",
        avid="ds/VCIO-123-1003",
        unique_content_id="sd6h4sh",
        url="https://test.com",
        date_collected=datetime.now(),
    )

    alias1 = AdvisoryAlias.objects.create(alias="CVE-2025-33053")
    alias2 = AdvisoryAlias.objects.create(alias="CVE-2025-10035")
    alias3 = AdvisoryAlias.objects.create(alias="CVE-2010-5278")
    adv1.aliases.add(alias1)
    adv2.aliases.add(alias2)
    adv3.aliases.add(alias3)

    improver = SigmaRulesImproverPipeline()
    improver.execute()

    assert len(DetectionRule.objects.all()) == 3
    sigma_rule = DetectionRule.objects.first()
    assert sigma_rule.rule_type == "sigma"
    assert sigma_rule.rule_metadata == {
        "author": "Swachchhanda Shrawan Poudel (Nextron Systems)",
        "date": "2025-06-13",
        "id": "04fc4b22-91a6-495a-879d-0144fec5ec03",
        "status": "experimental",
        "title": "Potential Exploitation of RCE Vulnerability CVE-2025-33053 - Image " "Load",
    }
    assert sigma_rule.advisory == adv1
    assert (
        sigma_rule.rule_text
        == "title: Potential Exploitation of RCE Vulnerability CVE-2025-33053 - Image Load\nid: 04fc4b22-91a6-495a-879d-0144fec5ec03\nrelated:\n    - id: abe06362-a5b9-4371-8724-ebd00cd48a04\n      type: similar\n    - id: 9a2d8b3e-f5a1-4c68-9e21-7d9e1cf8a123\n      type: similar\nstatus: experimental\ndescription: |\n    Detects potential exploitation of remote code execution vulnerability CVE-2025-33053\n    by monitoring suspicious image loads from WebDAV paths. The exploit involves malicious executables from\n    attacker-controlled WebDAV servers loading the Windows system DLLs like gdi32.dll, netapi32.dll, etc.\nreferences:\n    - https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-33053\n    - https://research.checkpoint.com/2025/stealth-falcon-zero-day/\nauthor: Swachchhanda Shrawan Poudel (Nextron Systems)\ndate: 2025-06-13\ntags:\n    - attack.command-and-control\n    - attack.execution\n    - attack.defense-evasion\n    - attack.t1218\n    - attack.lateral-movement\n    - attack.t1105\n    - detection.emerging-threats\n    - cve.2025-33053\nlogsource:\n    category: image_load\n    product: windows\ndetection:\n    selection_img_path:\n        Image|startswith: '\\\\\\\\'\n        Image|contains: '\\DavWWWRoot\\'\n    selection_img_bin:\n        Image|endswith:\n            - '\\route.exe'\n            - '\\netsh.exe'\n            - '\\makecab.exe'\n            - '\\dxdiag.exe'\n            - '\\ipconfig.exe'\n            - '\\explorer.exe'\n    condition: all of selection_*\nfalsepositives:\n    - Unknown\nlevel: high"
    )
