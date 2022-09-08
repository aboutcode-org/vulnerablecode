#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
from collections import namedtuple

from packageurl import PackageURL

logger = logging.getLogger(__name__)

# This code has been vendored from scancode.

# https://github.com/nexB/scancode-toolkit/blob/16ae20a343c5332114edac34c7b6fcf2fb6bca74/src/packagedcode/rpm.py#L91
class EVR(namedtuple("EVR", "epoch version release")):
    """
    The RPM Epoch, Version, Release tuple.
    """

    def __new__(self, version, release=None, epoch=None):
        """
        note: the sort order of the named tuple is the sort order.
        But for creation we put the rarely used epoch last with a default to None.
        """
        if not isinstance(epoch, int):
            if epoch and epoch.strip():
                logger.error("Invalid epoch: must be a number or empty.")
                return None
        if not version:
            logger.error("Version is required: {}".format(repr(version)))
            return None

        return super().__new__(EVR, epoch, version, release)

    def __str__(self, *args, **kwargs):
        return self.to_string()

    def to_string(self):
        if self.release:
            vr = f"{self.version}-{self.release}"
        else:
            vr = self.version

        if self.epoch:
            vr = ":".join([str(self.epoch), vr])
        return vr


# https://github.com/nexB/scancode-toolkit/blob/16ae20a343c5332114edac34c7b6fcf2fb6bca74/src/packagedcode/nevra.py#L36
def from_name(rpm_string):
    """
    Return an (E, N, V, R, A) tuple given a file name, by splitting
    [e:]name-version-release.arch into the four possible subcomponents.
    Default epoch, version, release and arch to None if not specified.
    Accepts RPM names with and without extensions
    """
    parse_nevra = re.compile("^" "(.*)" "-" "([^-]*)" "-" "([^-]*)" "\\." "([^.]*)" "$").match
    m = parse_nevra(rpm_string)
    if not m:
        return None
    n, v, r, a = m.groups()
    if ":" not in v:
        return None, n, v, r, a
    e, v = v.split(":", 1)
    if e.isdigit():
        e = int(e)
    return (e, n, v, r, a)


def rpm_to_purl(rpm_string, namespace):
    # FIXME: there is code in scancode to handle RPM conversion AND this should
    # be all be part of the packageurl library

    # FIXME: the comment below is not correct, this is the Epoch in the RPM version and not redhat specific
    # Red Hat uses `-:0` instead of just `-` to separate
    # package name and version

    # https://github.com/nexB/scancode-toolkit/blob/16ae20a343c5332114edac34c7b6fcf2fb6bca74/src/packagedcode/rpm.py#L310

    envra = from_name(rpm_string)

    if not envra:
        logger.error(f"Invalid RPM name can't get envra: {rpm_string}")
        return None
    sepoch, sname, sversion, srel, sarch = envra

    evr = EVR(sversion, srel, sepoch)
    if not evr:
        logger.error(f"Invalid RPM name can't get evr: {rpm_string}")
        return None
    src_evr = evr.to_string()
    src_qualifiers = {}
    if sarch:
        src_qualifiers["arch"] = sarch

    return PackageURL(
        type="rpm", namespace=namespace, name=sname, version=src_evr, qualifiers=src_qualifiers
    )
