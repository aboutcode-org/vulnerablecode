#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import io
import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path


def _safe_destination_path(destination: Path, member_name: str) -> Path:
    """
    Return a safe resolved destination path for ``member_name``.

    Raise ValueError if the path is absolute or escapes ``destination``.
    """
    member_path = Path(member_name)
    if member_path.is_absolute():
        raise ValueError(f"Unsafe absolute path in archive member: {member_name}")

    resolved = (destination / member_path).resolve()
    destination_resolved = destination.resolve()

    if os.path.commonpath([str(resolved), str(destination_resolved)]) != str(destination_resolved):
        raise ValueError(f"Path traversal attempt in archive member: {member_name}")

    return resolved


def _extract_tar_file(tar_file: tarfile.TarFile, destination: Path):
    errors = []

    for member in tar_file.getmembers():
        try:
            target = _safe_destination_path(destination, member.name)

            if member.issym() or member.islnk():
                errors.append(f"Skipping symlink member: {member.name}")
                continue

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            parent = target.parent
            parent.mkdir(parents=True, exist_ok=True)

            source = tar_file.extractfile(member)
            if source is None:
                continue

            with open(target, "wb") as out:
                shutil.copyfileobj(source, out)
        except Exception as e:
            errors.append(f"Failed extracting TAR member '{member.name}': {e}")

    return errors


def _extract_zip_file(zip_file: zipfile.ZipFile, destination: Path):
    errors = []

    for member in zip_file.infolist():
        try:
            target = _safe_destination_path(destination, member.filename)

            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            parent = target.parent
            parent.mkdir(parents=True, exist_ok=True)

            with zip_file.open(member, "r") as source, open(target, "wb") as out:
                shutil.copyfileobj(source, out)
        except Exception as e:
            errors.append(f"Failed extracting ZIP member '{member.filename}': {e}")

    return errors


def _extract_tar_zst(source_path: Path, destination: Path):
    errors = []

    try:
        import zstandard

        with open(source_path, "rb") as src:
            dctx = zstandard.ZstdDecompressor()
            with dctx.stream_reader(src) as reader:
                tar_stream = io.BytesIO(reader.read())
                with tarfile.open(fileobj=tar_stream, mode="r:") as tar_file:
                    errors.extend(_extract_tar_file(tar_file, destination))
        return errors
    except ImportError:
        pass
    except Exception as e:
        errors.append(f"Python zstandard extraction failed: {e}")

    # Fallback to system zstd when Python zstandard is unavailable.
    try:
        zstd = shutil.which("zstd")
        if not zstd:
            errors.append("zstd command not found for .tar.zst extraction")
            return errors

        result = subprocess.run(
            [zstd, "-dc", str(source_path)],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            errors.append(
                f"zstd extraction failed with code {result.returncode}: {result.stderr.decode('utf-8', errors='ignore')}"
            )
            return errors

        tar_stream = io.BytesIO(result.stdout)
        with tarfile.open(fileobj=tar_stream, mode="r:") as tar_file:
            errors.extend(_extract_tar_file(tar_file, destination))
    except Exception as e:
        errors.append(f"System zstd extraction failed: {e}")

    return errors


def extract_archive(source, destination):
    """Extract ``source`` archive into ``destination`` using secure native extraction."""
    source_path = Path(source)
    destination_path = Path(destination)
    destination_path.mkdir(parents=True, exist_ok=True)

    errors = []

    if str(source_path).endswith(".tar.zst"):
        errors.extend(_extract_tar_zst(source_path, destination_path))
    elif tarfile.is_tarfile(source_path):
        try:
            with tarfile.open(source_path, "r:*") as tar_file:
                errors.extend(_extract_tar_file(tar_file, destination_path))
        except Exception as e:
            errors.append(f"Failed opening TAR archive '{source_path}': {e}")
    elif zipfile.is_zipfile(source_path):
        try:
            with zipfile.ZipFile(source_path, "r") as zip_file:
                errors.extend(_extract_zip_file(zip_file, destination_path))
        except Exception as e:
            errors.append(f"Failed opening ZIP archive '{source_path}': {e}")
    else:
        errors.append(f"Unsupported archive format: {source_path}")

    if not errors:
        return {}

    return {str(source_path): errors}
