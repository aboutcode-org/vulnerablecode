#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from extractcode import api


def extract_archive(source, destination):
    """Extract an archive at `source` to `destination`directory."""
    errors = {}
    for event in api.extract_archive(source, destination):
        if event.done and event.errors:
            errors[str(event.source)] = event.errors

    return errors
