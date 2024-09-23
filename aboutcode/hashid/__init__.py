#
# Copyright (c) nexB Inc. and others. All rights reserved.
# Portions Copyright (c) The Python Software Foundation
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0 and Python-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from hashlib import sha256
from math import ceil
from pathlib import Path
from typing import Union
from urllib.parse import quote
from uuid import uuid4

from packageurl import PackageURL
from packageurl import normalize_qualifiers
from packageurl import normalize_subpath

"""
General purpose utilities to create Vulnerability Ids aka. VCID and content-defined, hash-based
paths to store Vulnerability and Package data using these paths in many balanced directories.

The reason why this is needed is to store many vulnerability and package metadata files, we need
to distribute these files in multiple directories and avoid too many files in the same directory
which makes every filesystem performance suffer.

In addition, when storing these files in Git repositories, we need to avoid creating any repository
with too many files that would make using this repository impactical or exceed the limits of some
repository hosting services.

Therefore we are storing vulnerability data using a directory tree using the first few characters
of the PURL hash of a package or the UUID of a vulnerability id.
"""

VULNERABILITY_REPO_NAME = "aboutcode-vulnerabilities"

PACKAGE_REPOS_NAME_PREFIX = "aboutcode-packages"
PURLS_FILENAME = "purls.yml"
VULNERABILITIES_FILENAME = "vulnerabilities.yml"


def build_vcid(prefix="VCID"):
    """
    Return a new Vulnerable Code ID (aka. VCID) which is a strongly unique vulnerability
    identifier string using the provided ``prefix``. A VCID is composed of a four letter prefix, and
    three segments composed of four letters and dihits each separated by a dash.
    For example::
    >>> import re
    >>> vcid = build_vcid()
    >>> assert re.match('VCID(-[a-hjkm-z1-9]{4}){3}', vcid), vcid

    We were mistakenly not using enough bits. The symptom was that the last
    segment of the VCID was always strting with "aaa" This ensure we are now OK:
    >>> vcids = [build_vcid() for _ in range(50)]
    >>> assert not any(vid.split("-")[-1].startswith("aaa") for vid in vcids)
    """
    uid = uuid4().bytes
    # we keep  three segments of 4 base32-encodee bytes, 3*4=12
    # which corresponds to 60 bits
    # becausee each base32 byte can store 5 bits (2**5 = 32)
    uid = base32_custom(uid)[:12].decode("utf-8").lower()
    return f"{prefix}-{uid[:4]}-{uid[4:8]}-{uid[8:12]}"


def get_vcid_yml_file_path(vcid: str):
    """
    Return the path to the vulnerability YAML file for a VCID.
    """
    return Path(VULNERABILITY_REPO_NAME) / vulnerability_yml_path(vcid)


# This cuxstom 32 characters alphabet is designed to avoid visually easily confusable characters:
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
    any directory and be able to find the path to a vulneravility file given its VCID distributed on
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


def get_package_base_dir(purl: Union[PackageURL, str]):
    """
    Return the base path to a Package directory (ignoring version) for a purl
    """
    path_elements = package_path_elements(purl)
    phash, core_path, _pversion, _extra_path = path_elements
    return Path(f"{PACKAGE_REPOS_NAME_PREFIX}-{phash}") / core_path


def get_package_purls_yml_file_path(purl: Union[PackageURL, str]):
    """
    Return the path to a Package purls.yml YAML for a purl.
    """
    return get_package_base_dir(purl) / PURLS_FILENAME


def get_package_vulnerabilities_yml_file_path(purl: Union[PackageURL, str]):
    """
    Return the path to a Package vulnerabilities.yml YAML for a purl.
    """
    return get_package_base_dir(purl) / VULNERABILITIES_FILENAME


def package_path_elements(purl: Union[PackageURL, str]):
    """
    Return 4-tuple of POSIX path strings crafted from the ``purl`` package PURL string or object.
    The tuple members are: (purl_hash, core_path, purl.version, extra_path)
    These members can be joined using a POSIX "/" path separator to store package data distributed
    evenly in many directories, where package data of the same package is co-located in the same
    root directory.

    The approach is to distribute the files in many directories to avoid having too many data files
    in any directory and be able to find the path to the YAML data files for a package given its
    PURL. For this we use the first characters of the "purl hash" to construct a path.

    A purl hash has 8,192 possible values, meaning 8,192 directories or repositories, basically used
    as a hash table. Given an estimated count of packages of about 30 million in mid 2024, this
    gives ample distribution of about 4,000 packages in each of these top level directories and some
    room to grow.

    The size to store compressed package metadata is guesstimated to be 1MB on average and 10MB for
    a full scan. This means that each directory will store 4K * 10MB ~= 4 GB. This should keep
    backing git repositories to a reasonable size, below 5GB.

    The storage scheme is designed to create this path structure:

    <short-purl-hash> : top level directory or repository
      <type>/<namespace>/<name> : sub directories
        purls.yml : YAML file with known versions for this package ordered from oldest to newest
        vulnerabilities.yml : YAML file with known vulnerabilities affecting (and fixed by) this package

        <version> : one sub directory for each version
          metadata.yml : ABOUT YAML file with package origin and license metadata for this version
          scancode-scan.yml : a scancode scan for this package version
          foo-scan.yml : a scan for this package version created with tool foo
          sbom.cdx.1.4.json : a CycloneDX SBOM
          sbom.cdx.1.5.json : a CycloneDX SBOM
          sbom.spdx.2.2.json : a SPDX SBOM
          .... other files

          <extra_path> : one sub directory for each quote-encoded <qualifiers#supath> if any
            metadata.yml : ABOUT YAML file with package origin and license metadata for this version
            scancode-scan.yml : a scancode scan for this package version
            foo-scan.yml : a scan for this package version created with tool foo
            sbom.cdx.1.4.json : a CycloneDX SBOM
            ... other files

    Some examples:

    We keep the same prefix for different versions::

    >>> package_path_elements("pkg:pypi/license_expression@30.3.1")
    ('1050', 'pypi/license-expression', '30.3.1', '')
    >>> package_path_elements("pkg:pypi/license_expression@10.3.1")
    ('1050', 'pypi/license-expression', '10.3.1', '')

    We encode with quotes, avoid double encoding of already quoted parts to make subpaths easier
    for filesystems::

    >>> package_path_elements("pkg:pypi/license_expression@30.3.1?foo=bar&baz=bar#sub/path")
    ('1050', 'pypi/license-expression', '30.3.1', 'baz%3Dbar%26foo%3Dbar%23sub%2Fpath')

    >>> purl = PackageURL(
    ...     type="pypi",
    ...     name="license_expression",
    ...     version="b#ar/?30.3.2!",
    ...     qualifiers=dict(foo="bar"),
    ...     subpath="a/b/c")
    >>> package_path_elements(purl)
    ('1050', 'pypi/license-expression', 'b%23ar%2F%3F30.3.2%21', 'foo%3Dbar%23a%2Fb%2Fc')
    """
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)

    purl_hash = get_purl_hash(purl)

    if ns := purl.namespace:
        ns_name = f"{ns}/{purl.name}"
    else:
        ns_name = purl.name

    extra_path = ""
    if pq := purl.qualifiers:
        # note that we percent-quote everything including the / character
        extra_path = quote_more(normalize_qualifiers(pq, encode=True))
    if psp := purl.subpath:
        psp = normalize_subpath(psp, encode=True)
        extra_path += quote_more(f"#{psp}")

    core_path = f"{purl.type}/{ns_name}"

    return purl_hash, core_path, quote_more(purl.version), extra_path


def quote_more(qs):
    """
    Return a quoted string from ``qs`` string by quoting all non-quoted characters ignoring already
    quoted characters. This makes the quoted string safer to use in a path.

    For example::
    >>> quote_more("foo")
    'foo'

    >>> quote_more("foo/bar")
    'foo%2Fbar'

    >>> quote_more("foo%2Fbar")
    'foo%2Fbar'
    """
    if not qs:
        return qs
    try:
        return quote(qs, safe="%")
    except Exception as e:
        raise Exception(f"Failed to quote_more: {qs!r}") from e


def get_core_purl(purl: Union[PackageURL, str]):
    """
    Return a new "core" purl from a ``purl`` object, dropping version, qualifiers and subpath.
    """
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)

    purld = purl.to_dict()
    del purld["version"]
    del purld["qualifiers"]
    del purld["subpath"]
    return PackageURL(**purld)


def get_purl_hash(purl: Union[PackageURL, str], _bit_count: int = 13) -> str:
    """
    Return a short lower cased hash string from a ``purl`` string or object. The PURL is normalized
    and we drop its version, qualifiers and subpath.

    This function takes a normalized PURL string and a ``_bit_count`` argument defaulting to 13 bits
    which represents 2**13 = 8192 possible hash values. It returns a fixed length short hash string
    that is left-padded with zeros.

    The hash length is derived from the bit_count and the number of bits-per-byte stored in an hex
    encoding of this bits count. For 13 bits, this means up to 4 characters.

    The function is carefully designed to be portable across tech stacks and easy to implement in
    many programming languages:

    - the hash is computed using sha256 which is available is all common language,
    - the hash is using simple lowercased HEX encoding,
    - we use simple arithmetics on integer with modulo.

    The processing goes through these steps:

    First, a SHA256 hash computed on the PURL bytes encoded as UTF-8.

    Then, the hash digest bytes are converted to an integer, which is reduced modulo the largest
    possible value for the bit_count.

    Finally, this number is converted to hex, left-padded with zero up to the hash_length, and
    returned as a lowercase string.

    For example::

    The hash does not change with version or qualifiers::
    >>> get_purl_hash("pkg:pypi/univers@30.12.0")
    '1289'
    >>> get_purl_hash("pkg:pypi/univers@10.12.0")
    '1289'
    >>> get_purl_hash("pkg:pypi/univers@30.12.0?foo=bar#sub/path")
    '1289'

    The hash is left padded with zero if it::
    >>> get_purl_hash("pkg:pypi/expressionss")
    '0057'

    We normalize the PURL. Here pypi normalization always uses dash for underscore ::

    >>> get_purl_hash("pkg:pypi/license_expression")
    '1050'
    >>> get_purl_hash("pkg:pypi/license-expression")
    '1050'

    Originally from:
    https://github.com/nexB/purldb/pull/235/files#diff-a1fd023bd42d73f56019d540f38be711255403547add15108540d70f9948dd40R154
    """

    core_purl = get_core_purl(purl).to_string()
    # compute the hash from a UTF-8 encoded string
    purl_bytes = core_purl.encode("utf-8")
    hash_bytes = sha256(purl_bytes).digest()
    # ... converted to integer so we can truncate with modulo. Note that we use big endian.
    hash_int = int.from_bytes(hash_bytes, "big")
    # take a modulo based on bit count to truncate digest to the largest int value for the bitcount
    max_int = 2**_bit_count
    short_hash = hash_int % max_int
    # maximum number of hex characters in the hash string
    bits_per_hex_byte = 4
    num_chars_in_hash = ceil(_bit_count / bits_per_hex_byte)
    # return an hex "x" string left padded with 0
    return f"{short_hash:0{num_chars_in_hash}x}".lower()
