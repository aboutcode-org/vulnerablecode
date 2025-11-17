#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from traceback import format_exc as traceback_format_exc
from typing import Callable
from typing import Union

from fetchcode.package_versions import SUPPORTED_ECOSYSTEMS as FETCHCODE_SUPPORTED_ECOSYSTEMS
from fetchcode.package_versions import versions
from packageurl import PackageURL


def get_versions(purl: Union[PackageURL, str], logger: Callable = None):
    """Return set of known versions for the given purl."""
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)

    if purl.type not in FETCHCODE_SUPPORTED_ECOSYSTEMS:
        return

    try:
        return {v.value.lstrip("vV") for v in versions(str(purl))}
    except Exception as e:
        if logger:
            logger(
                f"Error while fetching known versions for {purl!s}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )
