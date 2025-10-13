#
# Copyright (c) nexB Inc. and others. All rights reserved.
# Portions Copyright (c) The Python Software Foundation
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 and Python-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from uuid import uuid4


"""
General purpose utilities to create Vulnerability Ids aka. VCID.

Therefore we are storing vulnerability data using a directory tree using the
first few characters of the PURL hash of a package or the UUID of a
vulnerability id.
"""

VULNERABILITY_REPO_NAME = "aboutcode-vulnerabilities"


def build_vcid(prefix="VCID"):
    """
    Return a new Vulnerable Code ID (aka. VCID) which is a strongly unique
    vulnerability identifier string using the provided ``prefix``. A VCID is
    composed of a four letter prefix, and three segments composed of four
    letters and digits each separated by a dash.

    For example::
    >>> import re
    >>> vcid = build_vcid()
    >>> assert re.match('VCID(-[a-hjkm-z1-9]{4}){3}', vcid), vcid

    We were mistakenly not using enough bits. The symptom was that the last
    segment of the VCID was always string with "aaa" This ensure we are now OK:
    >>> vcids = [build_vcid() for _ in range(50)]
    >>> assert not any(vid.split("-")[-1].startswith("aaa") for vid in vcids)
    """
    uid = uuid4().bytes
    # we keep  three segments of 4 base32-encoded bytes, 3*4=12
    # which corresponds to 60 bits
    # because each base32 byte can store 5 bits (2**5 = 32)
    uid = base32_custom(uid)[:12].decode("utf-8").lower()
    return f"{prefix}-{uid[:4]}-{uid[4:8]}-{uid[8:12]}"


def get_vcid_yml_file_path(vcid: str):
    """
    Return the path to the vulnerability YAML file for a VCID.
    """
    return Path(VULNERABILITY_REPO_NAME) / vulnerability_yml_path(vcid)


# This custom 32 characters alphabet is designed to avoid visually easily confusable characters:
# i and l
# 0 and o
_base32_alphabet = b"abcdefghjkmnpqrstuvwxyz123456789"
_b32tab = [bytes((i,)) for i in _base32_alphabet]
_base32_table = [a + b for a in _b32tab for b in _b32tab]

base32_custom_alphabet = _base32_alphabet.decode("utf-8")


def base32_custom(btes):
    """
    Encode the ``btes`` bytes using a custom Base32 encoding with a custom alphabet and return a
    lowercase byte string. This alphabet is designed to avoid confusable characters.

    Not meant for general purpose Base32 encoding as this is not designed to ever be decoded.
    Code copied and modified from the Python Standard Library: base64._b32encode function

    For example::
    >>> base32_custom(b'abcd')
    b'abtze25e'

    >>> base32_custom(b'abcde00000xxxxxPPPPP')
    b'pfugg3dfga2dapbtsb6ht8d2mbjfaxct'
    """

    encoded = bytearray()
    from_bytes = int.from_bytes

    for i in range(0, len(btes), 5):
        c = from_bytes(btes[i : i + 5], "big")  # big-endian
        encoded += (
            _base32_table[c >> 30]  # bits 1 - 10
            + _base32_table[(c >> 20) & 0x3FF]  # bits 11 - 20
            + _base32_table[(c >> 10) & 0x3FF]  # bits 21 - 30
            + _base32_table[c & 0x3FF]  # bits 31 - 40
        )
    return bytes(encoded)


def vulnerability_yml_path(vcid):
    """
    Return the path to a vulnerability YAML file crafted from the ``vcid`` VCID vulnerability id.

    The approach is to distribute the files in many directories to avoid having too many files in
    any directory and be able to find the path to a vulnerability file given its VCID distributed on
    the first two characters of the UUID section of a VCID.

    The UUID is using a base32 encoding, hence keeping two characters means 32 x 32 = 1024
    possibilities, meaning 1024 directories. Given a current count of vulnerabilities of about 300K,
    mid 2024 this gives ample distribution of about 1000 vulnerabilities in each of 1000 directories
    and plenty of room to grow.

    The serialized vulnerability data should about 300MB compressed and should be storable in single
    Git repository.

    For example::
    >>> vulnerability_yml_path("VCID-s9bw-m429-aaaf")
    's9/VCID-s9bw-m429-aaaf.yml'
    """
    prefix = vcid[5 : 5 + 2]
    return f"{prefix}/{vcid}.yml"
