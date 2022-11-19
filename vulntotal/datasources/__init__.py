#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnTotal software is licensed under the Apache License version 2.0.
# Data generated with VulnTotal require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnTotal or any VulnTotal
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnTotal and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnTotal should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnTotal is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import glob
import importlib
import inspect
from os.path import basename
from os.path import dirname
from os.path import isfile
from os.path import join

from vulntotal.validator import DataSource

DATASOURCE_REGISTRY = {}
files = glob.glob(join(dirname(__file__), "*.py"))
modules = [
    f"vulntotal.datasources.{basename(f)[:-3]}"
    for f in files
    if isfile(f) and not f.endswith("__init__.py")
]


for module in modules:
    for name, cls in inspect.getmembers(importlib.import_module(module), inspect.isclass):
        if cls.__module__ == module and cls.__base__ == DataSource:
            DATASOURCE_REGISTRY[cls.__module__.split(".")[-1]] = cls
            break
