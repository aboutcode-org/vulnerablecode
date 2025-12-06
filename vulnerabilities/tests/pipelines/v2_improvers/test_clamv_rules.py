#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

import pytest

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import DetectionRule
from vulnerabilities.pipelines.v2_improvers.clamav_rules import ClamVRulesImproverPipeline

BASE_DIR = Path(__file__).resolve().parent
TEST_REPO_DIR = (BASE_DIR / "../../test_data/clamav").resolve()


@pytest.mark.django_db
@mock.patch("vulnerabilities.pipelines.v2_improvers.clamav_rules.extract_cvd")
@mock.patch("vulnerabilities.pipelines.v2_improvers.clamav_rules.requests.get")
def test_clamav_rules_db_improver(mock_requests_get, mock_extract_cvd):
    mock_resp = MagicMock()
    mock_resp.iter_content.return_value = [b"fake data"]
    mock_resp.raise_for_status.return_value = None
    mock_requests_get.return_value = mock_resp

    mock_extract_cvd.return_value = TEST_REPO_DIR

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

    alias1 = AdvisoryAlias.objects.create(alias="CVE-2019-1199")
    alias2 = AdvisoryAlias.objects.create(alias="CVE-2020-0720")
    alias3 = AdvisoryAlias.objects.create(alias="CVE-2020-0722")

    adv1.aliases.add(alias1)
    adv2.aliases.add(alias2)
    adv3.aliases.add(alias3)

    improver = ClamVRulesImproverPipeline()
    improver.execute()

    assert DetectionRule.objects.count() == 14
    assert DetectionRule.objects.get(advisory=adv1)
    assert DetectionRule.objects.get(advisory=adv2)
    assert DetectionRule.objects.get(advisory=adv3)
    assert [
        (detection_rule.rule_type, detection_rule.rule_text, detection_rule.source_url)
        for detection_rule in DetectionRule.objects.all()
    ] == [
        (
            "clamav",
            "{'hash': 'af9a2ce339b3a314cd8ce31f4e2489a5', 'file_size': '149420', 'name': 'Archive.Malware.Agent-7116646-0', 'line_num': 1}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'hash': 'ab51de8588946f1332d53dd53bac8056', 'file_size': '48580', 'name': 'Html.Malware.Agent-7116647-0', 'line_num': 2}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'hash': '3f70569ac131833698c3d1c20e0123ca', 'file_size': '676', 'name': 'Html.Malware.Agent-7116648-0', 'line_num': 3}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'hash': 'df6634d021a6df4d17f005e507beac88', 'file_size': '6268', 'name': 'Win.Exploit.CVE_2019_1199-7116649-2', 'line_num': 4}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'hash': '27ebcd8c72e6e3c7f4a64dc68b95dd8a', 'file_size': '173248', 'name': 'Html.Malware.Agent-7116650-0', 'line_num': 5}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'hash': '8745d432f7027e65178e92b2239bef25', 'file_size': '384634', 'name': 'Archive.Malware.Agent-7116651-0', 'line_num': 6}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'hash': '63d1a25066c121253febc907850b1852', 'file_size': '50185', 'name': 'Html.Malware.Agent-7116652-0', 'line_num': 7}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'hash': '92233ed6889cd0ba7bf632e3f45fc950', 'file_size': '97134', 'name': 'Html.Malware.Agent-7116653-0', 'line_num': 8}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'name': 'Win.Exploit.CVE_2020_0720-7578647-1', 'target_type': '1', 'offset': '*', 'hex_signature': '240C1400000068E8214000660F1344241C897C2414C744241805000000E80EFEFFFF83C4048D44240C50FF1544204000', 'line_num': 1}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'name': 'Win.Exploit.CVE_2020_0731-7583553-0', 'target_type': '1', 'offset': '*', 'hex_signature': '83C4088B55F0526AF48B45FC50FF15D4C146008945E46A006A006A108B4D', 'line_num': 2}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'name': 'Win.Exploit.CVE_2020_0722-7583689-1', 'target_type': '1', 'offset': '*', 'hex_signature': '488B555033C9FF15A1F100004889057AB10000488B0D73B10000FF1575F10000EB86', 'line_num': 3}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'name': 'Win.Ransomware.MailTo-7586723-0', 'target_type': '1', 'offset': '*', 'hex_signature': '496e746572666163345c7b62313936623238372d626162342d313031612d623639632d3030616130303334316430377d*4c616d616e74696e652e537469636b7950617373776f7264', 'line_num': 4}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'name': 'Win.Trojan.Emotet-7587729-1', 'target_type': '1', 'offset': '*', 'hex_signature': '565053e801000000cc5889c3402d00e016002dacb00b1005a3b00b10803bcc7519c60300bb00100000682ece177a680f9067565350e80a00000083c000894424085b58c35589e5505351568b75088b4d0cc1e9028b45108b5d1485c9740a3106011e83c60449ebf25e595b58c9c21000', 'line_num': 5}",
            "https://database.clamav.net/main.cvd",
        ),
        (
            "clamav",
            "{'name': 'Win.Trojan.Hoplight-7587747-0', 'target_type': '1', 'offset': '*', 'hex_signature': '4e6574776f726b20554450205472616365204d616e6167656d656e742053657276696365*6d646e6574757365*554450547263537663', 'line_num': 6}",
            "https://database.clamav.net/main.cvd",
        ),
    ]
