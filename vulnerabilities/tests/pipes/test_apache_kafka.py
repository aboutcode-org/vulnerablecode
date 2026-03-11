#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from pathlib import Path
from unittest import TestCase

from bs4 import BeautifulSoup

from vulnerabilities.pipes.apache_kafka import get_original_advisory
from vulnerabilities.pipes.apache_kafka import parse_range
from vulnerabilities.pipes.apache_kafka import parse_summary
from vulnerabilities.tests.pipelines import TestLogger

TEST_DATA = Path(__file__).parent.parent / "test_data" / "apache_kafka"


class TestPipeApacheKafka(TestCase):
    def setUp(self):
        self.logger = TestLogger()
        cve_list = TEST_DATA / "cve-list-2026_01_23.html"
        advisory_data = open(cve_list).read()
        soup = BeautifulSoup(advisory_data, features="lxml")
        self.tables = soup.find(class_="td-content").find_all("table")
        self.tables = list(self.tables)

    def test_vulnerability_pipes_apache_kafka_get_summary(self):
        table = self.tables[0]
        cve_h2 = table.find_previous("h2")

        result = parse_summary(
            cve_h2=cve_h2,
            table=table,
        )
        expected = (
            "In CVE-2023-25194, we announced the RCE/Denial of service attack via SASL "
            "JAAS JndiLoginModule configuration in Kafka Connect API. But not only Kafka "
            "Connect API is vulnerable to this attack, the Apache Kafka brokers also have "
            "this vulnerability. To exploit this vulnerability, the attacker needs to be "
            "able to connect to the Kafka cluster and have the AlterConfigs permission on "
            "the cluster resource. Since Apache Kafka 3.4.0, we have added a system property "
            '("-Dorg.apache.kafka.disallowed.login.modules") to disable the problematic login '
            "modules usage in SASL JAAS configuration. Also by default "
            "“com.sun.security.auth.module.JndiLoginModule” is disabled in Apache Kafka 3.4.0, "
            "and “com.sun.security.auth.module.JndiLoginModule,com.sun.security.auth.module.LdapLoginModule” "
            "is disabled by default in Apache Kafka 3.9.1/4.0.0. "
        )
        self.assertEqual(result, expected)

    def test_vulnerability_pipes_apache_kafka_get_original_advisory(self):
        table = self.tables[0]
        cve_h2 = table.find_previous("h2")

        result = get_original_advisory(
            cve_h2=cve_h2,
            table=table,
        )

        self.assertIn('id="CVE-2025-27819"', result)
        self.assertIn("<p>2.0.0 - 3.3.2</p>", result)

    def test_vulnerability_pipes_apache_kafka_parse_range(self):
        affected = "2.8.0 - 2.8.1, 3.0.0 - 3.0.1, 3.1.0 - 3.1.1, 3.2.0 - 3.2.1"

        result_affected = parse_range(affected)
        result_affected = [str(const) for const in result_affected]
        expected_affected = [
            ">=2.8.0",
            "<=2.8.1",
            ">=3.0.0",
            "<=3.0.1",
            ">=3.1.0",
            "<=3.1.1",
            ">=3.2.0",
            "<=3.2.1",
        ]

        self.assertCountEqual(result_affected, expected_affected)

    def test_vulnerability_pipes_apache_kafka_parse_range_dirty_range(self):
        affected = "Apache Kafka Connect API (connect-api,connect-runtime) : 2.3.0 - 3.3.2"

        result_affected = parse_range(affected)
        result_affected = [str(const) for const in result_affected]
        expected_affected = [">=2.3.0", "<=3.3.2"]

        self.assertCountEqual(result_affected, expected_affected)
