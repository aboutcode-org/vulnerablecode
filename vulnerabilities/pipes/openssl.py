#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from urllib.parse import parse_qs
from urllib.parse import urlparse

from univers.version_constraint import VersionConstraint
from univers.versions import OpensslVersion

from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.utils import get_item


def parse_affected_fixed(affected):
    impact_lower = affected.get("version")
    affected_constraint = []
    fixed_version = None

    if not impact_lower:
        return affected_constraint, fixed_version

    if impact_upper := affected.get("lessThan"):
        fixed_version = impact_upper
        affected_constraint.append(
            VersionConstraint(
                comparator="<",
                version=OpensslVersion(string=impact_upper),
            )
        )
    elif impact_upper := affected.get("lessThanOrEqual"):
        affected_constraint.append(
            VersionConstraint(
                comparator="<=",
                version=OpensslVersion(string=impact_upper),
            )
        )

    lower_comp = "=" if not affected_constraint else ">="
    affected_constraint.append(
        VersionConstraint(
            comparator=lower_comp,
            version=OpensslVersion(string=impact_lower),
        )
    )

    return affected_constraint, fixed_version


def get_commit_patch(url, logger):
    """Return PackageCommitPatchData from OpenSSL commit url."""

    vcs_url = "https://github.com/openssl/openssl/"
    hash = None

    if url.startswith("https://github.openssl.org/"):
        # unknow vcs url, these are instead stored as references.
        return

    if url.startswith("https://github.com/"):
        vcs_url, hash = url.split("/commit/")
    elif url.startswith("https://git.openssl.org/"):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, separator=";")
        if "h" in params:
            # git.openssl.org has moved to github.com/openssl/openssl
            hash = get_item(params, "h", 0)

    if not hash:
        logger(f"Unsupported commit url {url}")
        return

    return PackageCommitPatchData(
        vcs_url=vcs_url,
        commit_hash=hash[:40],
    )


def get_reference(reference_name, tag, reference_url):
    name = reference_name.lower() if reference_name else ""

    ref_type = (
        AdvisoryReference.COMMIT
        if "commit" in name or tag == "patch"
        else AdvisoryReference.ADVISORY
        if "advisory" in name
        else AdvisoryReference.OTHER
    )

    return ReferenceV2(
        reference_id=reference_name or tag,
        reference_type=ref_type,
        url=reference_url,
    )
