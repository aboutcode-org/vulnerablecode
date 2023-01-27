#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import bz2
import logging
import xml.etree.ElementTree as ET

import requests

from vulnerabilities.importer import OvalImporter

logger = logging.getLogger(__name__)


class UbuntuImporter(OvalImporter):
    spdx_license_expression = "LicenseRef-scancode-other-permissive"
    notice = """
    From: Seth Arnold <seth.arnold@canonical.com>
    Date: Wed, Jan 25, 2023 at 2:02 AM
    Subject: Re: [ubuntu-hardened] Usage of Ubuntu Security Data in VulnerableCode
    To: Tushar Goel <tushar.goel.dav@gmail.com>
    Cc: <ubuntu-hardened@lists.ubuntu.com>, Philippe Ombredanne <pombredanne@nexb.com>, jmhoran@nexb.com <jmhoran@nexb.com>
    
    
    On Wed, Jan 11, 2023 at 06:27:38PM +0530, Tushar Goel wrote:
    > We would like to integrate the Ubuntu usn data[1][2] and
    > Ubuntu security data (OVAL format)[3] in vulnerablecode[4]
    > which is a FOSS db of FOSS vulnerability data. We were not
    > able to know under which license this security data comes.
    > We would be grateful to have your acknowledgement over usage of
    > the ubuntu security data in vulnerablecode and have
    > some kind of licensing declaration from your side.
    
    Hello Tushar, we do not have an explicit license on this data.
    
    We share our data with the intention that others will use it. Please
    feel free to use it for the general furtherance of security.
    
    Much of the data that's contained within our databases is sourced from
    third parties, who also shared their data with the intention that others
    will use it. I'm not sure what it would look like to try to put a license
    on data that is crowd-sourced from thousands of contributors. (If you were
    to start such a project today, it'd probably be one of the first things to
    formalize. But when CVE was started two decades ago, the primary goal was
    sharing knowledge and simplifying the vulnerability remediation process,
    and licensing the data was, as far as I can remember, not considered.
    Sharing was the goal.)
    
    I will ask that vulnerablecode 'be nice' to our infrastructure that
    hosts the databases -- some automated uses of our infrastructure by
    vulnerability scanner tools has lead to significant load and engineering
    effort. In general, please prefer a small handful of systems updating
    mirrors roughly twice a day rather than thousands of hosts pulling
    data hourly.
    
    Thanks
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we could avoid setting translations, and have it
        # set by default in the OvalParser, but we don't yet know
        # whether all OVAL providers use the same format
        self.translations = {"less than": "<"}

    def _fetch(self):
        base_url = "https://people.canonical.com/~ubuntu-security/oval"
        releases = ["bionic", "trusty", "focal", "eoan", "xenial"]
        for release in releases:
            file_url = f"{base_url}/com.ubuntu.{release}.cve.oval.xml.bz2"  # nopep8
            logger.info(f"Fetching Ubuntu Oval: {file_url}")
            response = requests.get(file_url)
            if response.status_code != requests.codes.ok:
                logger.error(
                    f"Failed to fetch Ubuntu Oval: HTTP {response.status_code} : {file_url}"
                )
                continue

            extracted = bz2.decompress(response.content)
            yield (
                {"type": "deb", "namespace": "ubuntu"},
                ET.ElementTree(ET.fromstring(extracted.decode("utf-8"))),
            )
