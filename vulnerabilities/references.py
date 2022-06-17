#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.importer import Reference


class XsaReference(Reference):
    """
    A Xen advisory reference. See https://xenbits.xen.org/xsa
    """

    @classmethod
    def from_id(cls, xsa_id):
        """
        Return a new XsaReference from an XSA-XXXX id.
        """
        if not xsa_id or not xsa_id.lower().startswith("xsa"):
            return ValueError(f"Not a Xen reference. Does not start with XSA: {xsa_id!r}")
        _, numid = xsa_id.rsplit("-")
        return cls(
            reference_id=xsa_id,
            url=f"https://xenbits.xen.org/xsa/advisory-{numid}.html",
        )


class ZbxReference(Reference):
    """
    A Zabbix advisory reference. See https://support.zabbix.com
    """

    @classmethod
    def from_id(cls, zbx_id):
        """
        Return a new ZbxReference from an ZBX-XXXX id.
        """
        if not zbx_id or not zbx_id.lower().startswith("zbx"):
            return ValueError(f"Not a Zabbix reference. Does not start with ZBX: {zbx_id!r}")
        return cls(
            reference_id=zbx_id,
            url=f"https://support.zabbix.com/browse/{zbx_id}",
        )


class WireSharkReference(Reference):
    """
    A Wireshark advisory reference. See https://www.wireshark.org/security
    """

    @classmethod
    def from_id(cls, wnpa_sec_id):
        """
        Return a new WireSharkReference from an wnpa-sec-XXXX id.
        """
        if not wnpa_sec_id or not wnpa_sec_id.lower().startswith("wnpa-sec"):
            return ValueError(
                f"Not a WireShark reference. Does not start with wnpa-sec: {wnpa_sec_id!r}"
            )
        return cls(
            reference_id=wnpa_sec_id,
            url=f"https://www.wireshark.org/security/{wnpa_sec_id}.html",
        )
