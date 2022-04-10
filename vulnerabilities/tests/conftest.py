#
# Copyright (c)  nexB Inc. and others. All rights reserved.
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

import pytest


@pytest.fixture
def no_mkdir(monkeypatch):
    monkeypatch.delattr("os.mkdir")


@pytest.fixture
def no_rmtree(monkeypatch):
    monkeypatch.delattr("shutil.rmtree")


# TODO: Ignore these tests for now but we need to migrate each one of them to the new struture.
# Step 1: Fix importer_yielder: https://github.com/nexB/vulnerablecode/issues/501
# Step 2: Run test for importer only if it is activated (pytestmark = pytest.mark.skipif(...))
# Step 3: Migrate all the tests
collect_ignore = [
    "test_apache_httpd.py",
    "test_apache_kafka.py",
    "test_apache_tomcat.py",
    "test_api.py",
    "test_archlinux.py",
    "test_data_source.py",
    "test_debian_oval.py",
    "test_debian.py",
    "test_elixir_security.py",
    "test_gentoo.py",
    "test_importer_yielder.py",
    "test_istio.py",
    "test_models.py",
    "test_mozilla.py",
    "test_msr2019.py",
    "test_npm.py",
    "test_openssl.py",
    "test_package_managers.py",
    "test_postgresql.py",
    "test_redhat_importer.py",
    "test_retiredotnet.py",
    "test_ruby.py",
    "test_rust.py",
    "test_safety_db.py",
    "test_suse_backports.py",
    "test_suse.py",
    "test_suse_scores.py",
    "test_ubuntu.py",
    "test_ubuntu_usn.py",
    "test_upstream.py",
]
