#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import xml.etree.ElementTree as ET

import requests

from vulnerabilities.importer import OvalImporter


class DebianOvalImporter(OvalImporter):

    spdx_license_expression = "LicenseRef-scancode-other-permissive"
    license_url = "https://www.debian.org/license"
    notice = """
    From: Tushar Goel <tgoel@nexb.com>
    Date: Thu, May 12, 2022 at 11:42 PM +00:00
    Subject: Usage of Debian Security Data in VulnerableCode
    To: <team@security.debian.org>
    Hey,
    We would like to integrate the debian security data in vulnerablecode
    [1][2] which is a FOSS db of FOSS vulnerability data. We were not able
    to know under which license the debian security data comes. We would
    be grateful to have your acknowledgement over usage of the debian
    security data in vulnerablecode and have some kind of licensing
    declaration from your side.
    [1] - https://github.com/nexB/vulnerablecode
    [2] - https://github.com/nexB/vulnerablecode/pull/723
    Regards,
    From: Moritz Mühlenhoff <jmm@inutil.org>
    Date: Wed, May 17, 2022, 19:12 PM +00:00
    Subject: Re: Usage of Debian Security Data in VulnerableCode
    To: Tushar Goel <tgoel@nexb.com>
    Cc: <team@security.debian.org>
    Am Thu, May 12, 2022 at 05:12:48PM +0530 schrieb Tushar Goel:
    > Hey,
    >
    > We would like to integrate the debian security data in vulnerablecode
    > [1][2] which is a FOSS db of FOSS vulnerability data. We were not able
    > to know under which license the debian security data comes. We would
    > be grateful to have your acknowledgement over usage of the debian
    > security data in vulnerablecode and have some kind of licensing
    > declaration from your side.
    We don't have a specific license, but you have our endorsemen to
    reuse the data by all means :-)
    Cheers,
        Moritz
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we could avoid setting translations, and have it
        # set by default in the OvalParser, but we don't yet know
        # whether all OVAL providers use the same format
        self.translations = {"less than": "<"}

    def _fetch(self):
        releases = ["wheezy", "stretch", "jessie", "buster", "bullseye"]
        for release in releases:
            file_url = f"https://www.debian.org/security/oval/oval-definitions-{release}.xml"
            resp = requests.get(file_url).content
            yield (
                {"type": "deb", "namespace": "debian", "qualifiers": {"distro": release}},
                ET.ElementTree(ET.fromstring(resp.decode("utf-8"))),
            )
