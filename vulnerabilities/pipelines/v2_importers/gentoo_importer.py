#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Iterable

from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import EbuildVersionRange
from univers.versions import GentooVersion
from univers.versions import InvalidVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC


class GentooImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    repo_url = "git+https://anongit.gentoo.org/git/data/glsa.git"
    spdx_license_expression = "CC-BY-SA-4.0"
    # the license notice is at this url https://anongit.gentoo.org/ says:
    # The contents of this document, unless otherwise expressly stated, are licensed
    # under the [CC-BY-SA-4.0](https://creativecommons.org/licenses/by-sa/4.0/) license.
    license_url = "https://creativecommons.org/licenses/by-sa/4.0/"
    pipeline_id = "gentoo_importer_v2"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def advisories_count(self):
        advisory_dir = Path(self.vcs_response.dest_dir)
        return sum(1 for _ in advisory_dir.rglob("*.xml"))

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_path = Path(self.vcs_response.dest_dir)
        for file_path in base_path.glob("**/*.xml"):
            yield from self.process_file(file_path)

    def process_file(self, file):
        cves = []
        summary = ""
        xml_root = ET.parse(file).getroot()
        id = xml_root.attrib.get("id", "")
        glsa = "GLSA-" + id
        vuln_references = [
            ReferenceV2(
                reference_id=glsa,
                url=f"https://security.gentoo.org/glsa/{id}",
            )
        ]

        severities = []
        affected_packages = []
        for child in xml_root:
            if child.tag == "references":
                cves = self.cves_from_reference(child)

            if child.tag == "synopsis":
                summary = child.text

            if child.tag == "affected":
                affected_packages = []
                for purl, (affected_ranges, fixed_ranges) in get_affected_and_fixed_purls(
                    child, logger=self.log
                ):
                    affected_version_constraint = build_constraints(
                        affected_ranges, logger=self.log
                    )
                    fixed_version_constraint = build_constraints(fixed_ranges, logger=self.log)
                    affected_version_range = EbuildVersionRange(
                        constraints=affected_version_constraint
                    )
                    fixed_version_range = EbuildVersionRange(constraints=fixed_version_constraint)
                    affected_package = AffectedPackageV2(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version_range=fixed_version_range,
                    )
                    affected_packages.append(affected_package)

            if child.tag == "impact":
                severity_value = child.attrib.get("type")
                if severity_value:
                    severities.append(VulnerabilitySeverity(system=GENERIC, value=severity_value))

        yield AdvisoryData(
            advisory_id=glsa,
            aliases=cves,
            summary=summary,
            references_v2=vuln_references,
            severities=severities,
            affected_packages=affected_packages,
            url=f"https://security.gentoo.org/glsa/{id}",
            original_advisory_text=file,
        )

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()

    @staticmethod
    def cves_from_reference(reference):
        cves = []
        for child in reference:
            txt = child.text.strip()
            match = re.match(r"CVE-\d{4}-\d{4,}", txt)
            if match:
                cves.append(match.group())
        return cves


def build_constraints(constraint_pairs, logger):
    """
    Build a list of VersionConstraint objects from comparators, versions pairs.
    """
    constraints = []
    for comparator, version in constraint_pairs:
        try:
            constraint = VersionConstraint(version=GentooVersion(version), comparator=comparator)
            constraints.append(constraint)
        except InvalidVersion as e:
            logger(f"InvalidVersion constraints version: {version} error:{e}")
    return constraints


def get_affected_and_fixed_purls(affected_elem, logger):
    """
    Parses XML elements to extract PURLs associated with affected and fixed versions.
    """

    for pkg in affected_elem:
        name = pkg.attrib.get("name")
        if not name:
            continue

        pkg_ns, _, pkg_name = name.rpartition("/")
        # purl_components, (fixed_ranges_set, affected_ranges_set)
        purl_ranges_map = defaultdict(lambda: {"fixed_ranges": set(), "affected_ranges": set()})

        for info in pkg:
            # All possible values of info.attrib['range'] =
            # {'gt', 'lt', 'rle', 'rge', 'rgt', 'le', 'ge', 'eq'}
            # rge means revision greater than equals and rgt means revision greater than

            range_value = info.attrib.get("range")
            slot_value = info.attrib.get("slot")
            comparator_dict = {
                "gt": ">",
                "lt": "<",
                "ge": ">=",
                "le": "<=",
                "eq": "=",
                # "rle": "<=",
                # "rge": ">=",
                # "rgt": ">",
            }
            comparator = comparator_dict.get(range_value)
            if not comparator:
                logger(f"Unsupported range value {range_value}:{info.text}")
                continue

            if info.tag == "unaffected":
                purl_ranges_map[(pkg_name, pkg_ns, slot_value)]["fixed_ranges"].add(
                    (comparator, info.text)
                )

            elif info.tag == "vulnerable":
                purl_ranges_map[(pkg_name, pkg_ns, slot_value)]["affected_ranges"].add(
                    (comparator, info.text)
                )

        for (pkg_name, pkg_ns, slot_value), data in purl_ranges_map.items():
            qualifiers = {"slot": slot_value} if slot_value else {}
            purl = PackageURL(type="ebuild", name=pkg_name, namespace=pkg_ns, qualifiers=qualifiers)
            yield purl, (data["affected_ranges"], data["fixed_ranges"])
