#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
from datetime import datetime
from datetime import timezone

from aboutcode.pipeline import BasePipeline

from vulnerabilities.utils import classproperty

module_logger = logging.getLogger(__name__)


class VulnerableCodePipeline(BasePipeline):
    def log(self, message, level=logging.INFO):
        """Log the given `message` to the current module logger and execution_log."""
        now_local = datetime.now(timezone.utc).astimezone()
        timestamp = now_local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        message = f"{timestamp} {message}"
        module_logger.log(level, message)
        self.append_to_log(message)

    @classproperty
    def qualified_name(cls):
        """
        Fully qualified name prefixed with the module name of the pipeline used in logging.
        """
        return f"{cls.__module__}.{cls.__qualname__}"
