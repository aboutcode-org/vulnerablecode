#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pipeline import BasePipeline
from pipeline import BasePipelineRun
from vulnerabilities.utils import classproperty


class VulnerableCodePipeline(BasePipeline, BasePipelineRun):
    @classproperty
    def qualified_name(cls):
        """
        Fully qualified name prefixed with the module name of the improver used in logging.
        """
        return f"{cls.__module__}.{cls.__qualname__}"
