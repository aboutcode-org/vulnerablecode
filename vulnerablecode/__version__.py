#
# Copyright (c) nexB Inc. and others. All rights reserved.
# Copyright (c) 2026 CARIAD SE.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("vulnerablecode")
except PackageNotFoundError:
    # We are running from a git checkout, so we don't have metada
    from pathlib import Path

    import toml

    pyproject = toml.loads((Path(__file__).parent.parent.parent / "pyproject.toml").read_text())
    __version__ = pyproject["project"]["version"]
