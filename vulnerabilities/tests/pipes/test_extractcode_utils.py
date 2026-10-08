#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import io
import tarfile
from pathlib import Path

from vulnerabilities.pipes import extractcode_utils


def _build_tar_with_member(tar_path: Path, member_name: str, content: bytes):
    with tarfile.open(tar_path, "w") as tar:
        info = tarfile.TarInfo(name=member_name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))


def test_extract_archive_blocks_path_traversal(tmp_path):
    archive = tmp_path / "sample.tar"
    output = tmp_path / "out"

    _build_tar_with_member(archive, "../../escape.txt", b"oops")

    errors = extractcode_utils.extract_archive(source=archive, destination=output)

    assert str(archive) in errors
    assert not (tmp_path / "escape.txt").exists()


def test_extract_archive_extracts_safe_files(tmp_path):
    archive = tmp_path / "safe.tar"
    output = tmp_path / "out"

    _build_tar_with_member(archive, "nested/file.txt", b"ok")

    errors = extractcode_utils.extract_archive(source=archive, destination=output)

    assert errors == {}
    assert (output / "nested" / "file.txt").read_bytes() == b"ok"
