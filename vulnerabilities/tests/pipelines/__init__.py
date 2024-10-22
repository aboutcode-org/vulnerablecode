#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import io


class TestLogger:
    buffer = io.StringIO()

    def write(self, msg, level=None):
        self.buffer.write(msg)

    def getvalue(self):
        return self.buffer.getvalue()
