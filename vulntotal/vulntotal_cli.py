#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import concurrent.futures
import json
import math
import os
import pydoc

import click

# TODO: use saneyaml
import yaml
from packageurl import PackageURL
from texttable import Texttable
from univers.normalized_range import NormalizedVersionRanges

from vulnerabilities.package_managers import VERSION_API_CLASSES_BY_PACKAGE_TYPE
from vulntotal.datasources import DATASOURCE_REGISTRY
from vulntotal.validator import VendorData
from vulntotal.vulntotal_utils import get_item


@click.command()
@click.argument("purl", required=False)
@click.option(
    "--json",
    "json_output",
    type=click.File("w"),
    required=False,
    metavar="FILE",
    help="Write output as pretty-printed JSON to FILE. Use '-' to print on screen.",
)
@click.option(
    "--yaml",
    "yaml_output",
    type=click.File("w"),
    required=False,
    metavar="FILE",
    help="Write output as YAML to FILE. Use '-' to print on screen.",
)
@click.option(
    "-l",
    "--list",
    "list_source",
    is_flag=True,
    multiple=False,
    required=False,
    help="List available datasources.",
)

# hidden debug options
@click.option(
    "-e",
    "--enable",
    "enable",
    hidden=True,
    multiple=True,
    type=click.Choice(DATASOURCE_REGISTRY.keys()),
    required=False,
    help="Enable only this datasource. Repeat for multiple datasources. Used for debugging.",
)
@click.option(
    "-d",
    "--disable",
    "disable",
    hidden=True,
    multiple=True,
    type=click.Choice(DATASOURCE_REGISTRY.keys()),
    required=False,
    help="Disable this datasource. Repeat for multiple datasources. Used for debugging.",
)
@click.option(
    "--ecosystem",
    "ecosystem",
    hidden=True,
    is_flag=True,
    required=False,
    help="List package ecosystem supported by active datasources. Used for debugging.",
)
@click.option(
    "--raw",
    "raw_output",
    is_flag=True,
    hidden=True,
    multiple=False,
    required=False,
    help="Report the raw responses from each datasource. Used for debugging.",
)
@click.option(
    "--no-threading",
    "no_threading",
    is_flag=True,
    hidden=True,
    multiple=False,
    required=False,
    help="Query datasources sequentially. Used for debugging.",
)
@click.option(
    "-p",
    "--pagination",
    "pagination",
    is_flag=True,
    hidden=True,
    multiple=False,
    required=False,
    help="Enable default pagination. Used for debugging.",
)
@click.option(
    "--no-group",
    "no_group",
    is_flag=True,
    hidden=True,
    multiple=False,
    required=False,
    help="Do not group output by vulnerability/CVE. Used for debugging.",
)
@click.option(
    "--vers",
    "vers",
    is_flag=True,
    hidden=True,
    multiple=False,
    required=False,
    help="Show normalized vers. Used for debugging.",
)
@click.option(
    "--no-compare",
    "no_compare",
    is_flag=True,
    hidden=True,
    multiple=False,
    required=False,
    help="Do not compare datasource output. Used for debugging.",
)
@click.help_option("-h", "--help")
def handler(
    purl,
    list_source,
    enable,
    disable,
    ecosystem,
    raw_output,
    no_threading,
    pagination,
    json_output,
    yaml_output,
    no_group,
    vers,
    no_compare,
):
    """
    Search all the available vulnerabilities databases for the package-url PURL.
    """
    active_datasource = (
        get_enabled_datasource(enable)
        if enable
        else (get_undisabled_datasource(disable) if disable else DATASOURCE_REGISTRY)
    )

    if list_source:
        list_datasources()

    elif not active_datasource:
        click.echo("No datasource available!", err=True)

    elif ecosystem:
        list_supported_ecosystem(active_datasource)

    elif raw_output:
        if purl:
            get_raw_response(purl, active_datasource)

    elif json_output:
        write_json_output(purl, active_datasource, json_output, no_threading, no_group, no_compare)

    elif yaml_output:
        write_yaml_output(purl, active_datasource, yaml_output, no_threading, no_group, no_compare)

    elif no_group:
        prettyprint(purl, active_datasource, pagination, no_threading)

    elif purl:
        prettyprint_group_by_cve(purl, active_datasource, pagination, no_threading, vers, no_compare)


def get_valid_datasources(datasources):
    valid_datasources = {}
    unknown_datasources = []
    for datasource in datasources:
        key = datasource.lower()
        try:
            valid_datasources[key] = DATASOURCE_REGISTRY[key]
        except KeyError:
            unknown_datasources.append(key)
    if unknown_datasources:
        raise Exception(f"Unknown datasources: {unknown_datasources}")
    return valid_datasources


def get_undisabled_datasource(datasources):
    disabled = get_valid_datasources(datasources)
    return {key: value for key, value in DATASOURCE_REGISTRY.items() if key not in disabled}


def get_enabled_datasource(datasources):
    return get_valid_datasources(datasources)


def list_datasources():
    datasources = [x.upper() for x in list(DATASOURCE_REGISTRY)]
    click.echo("Currently supported datasources:")
    click.echo("\n".join(sorted(datasources)))


def list_supported_ecosystem(datasources):
    ecosystems = []
    for _key, datasource in datasources.items():
        vendor_supported_ecosystem = datasource.supported_ecosystem()
        ecosystems.extend([x.upper() for x in vendor_supported_ecosystem.keys()])

    active_datasource = [x.upper() for x in datasources.keys()]
    click.echo("Active datasources: %s\n" % ", ".join(sorted(active_datasource)))
    click.echo("Package ecosystem supported by active datasources")
    click.echo("\n".join(sorted(set(ecosystems))))


def formatted_row(datasource, advisory):
    if not advisory:
        return [datasource.upper(), "", "", ""]

    aliases = "\n".join(advisory.aliases)
    affected = "  ".join(advisory.affected_versions)
    fixed = "  ".join(advisory.fixed_versions)
    return [datasource.upper(), aliases, affected, fixed]


def get_raw_response(purl, datasources):
    all_raw_responses = {}
    for key, datasource in datasources.items():
        vendor = datasource()
        vendor_advisories = list(vendor.datasource_advisory(PackageURL.from_string(purl)))
        all_raw_responses[key] = vendor.raw_dump
    click.echo(json.dumps(all_raw_responses, indent=2))


def run_datasources(purl, datasources, no_threading=False):
    vulnerabilities = {}
    if not no_threading:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(datasources)) as executor:
            future_to_advisory = {
                executor.submit(
                    datasource().datasource_advisory, PackageURL.from_string(purl)
                ): datasource
                for key, datasource in datasources.items()
            }
            for future in concurrent.futures.as_completed(future_to_advisory):
                vendor = future_to_advisory[future].__name__[:-10].lower()
                try:
                    vendor_advisories = future.result()
                    vulnerabilities[vendor] = []
                    if vendor_advisories:
                        vulnerabilities[vendor].extend([advisory for advisory in vendor_advisories])
                except Exception as exc:
                    click.echo("%s  generated an exception: %s" % (vendor, exc))
    else:
        for key, datasource in datasources.items():
            vendor_advisories = datasource().datasource_advisory(PackageURL.from_string(purl))
            vulnerabilities[key] = []
            if vendor_advisories:
                vulnerabilities[key].extend([advisory for advisory in vendor_advisories])

    return vulnerabilities


class VulntotalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, VendorData) or isinstance(obj, NormalizedVersionRanges):
            return obj.to_dict()
        return json.JSONEncoder.default(self, obj)


def write_json_output(purl, datasources, json_output, no_threading, no_group, no_compare):
    results = {"purl": purl, "datasources": list(datasources.keys())}

    vulnerabilities = run_datasources(purl, datasources, no_threading)
    if no_group:
        results.update(vulnerabilities)
    else:
        grouped_by_cve = group_by_cve(vulnerabilities, PackageURL.from_string(purl), no_compare)
        results.update(grouped_by_cve)

    return json.dump(results, json_output, cls=VulntotalEncoder, indent=2)


def noop(self, *args, **kw):
    pass


yaml.emitter.Emitter.process_tag = noop


def write_yaml_output(purl, datasources, yaml_output, no_threading, no_group, no_compare):
    results = {"purl": purl, "datasources": list(datasources.keys())}

    vulnerabilities = run_datasources(purl, datasources, no_threading)
    if no_group:
        results.update(vulnerabilities)
    else:
        grouped_by_cve = group_by_cve(vulnerabilities, PackageURL.from_string(purl), no_compare)
        serialize_normalized_range(grouped_by_cve, no_compare)
        results.update(grouped_by_cve)

    return yaml.dump(results, yaml_output, default_flow_style=False, indent=2, sort_keys=False)


def serialize_normalized_range(grouped_by_cve, no_compare):
    if no_compare:
        return
    for cve, value in grouped_by_cve.items():
        if cve in ("NOCVE", "NOADVISORY"):
            continue
        for datasource, resources in value.items():
            for resource in resources:
                affected_versions = resource.get("normalized_affected_versions")
                fixed_versions = resource.get("normalized_fixed_versions")
                if isinstance(affected_versions, NormalizedVersionRanges):
                    resource["normalized_affected_versions"] = [
                        str(vers) for vers in affected_versions.version_ranges
                    ]
                if isinstance(fixed_versions, NormalizedVersionRanges):
                    resource["normalized_fixed_versions"] = [
                        str(vers) for vers in fixed_versions.version_ranges
                    ]


def prettyprint(purl, datasources, pagination, no_threading):
    vulnerabilities = run_datasources(purl, datasources, no_threading)
    if not vulnerabilities:
        return

    active_datasources = ", ".join(sorted([x.upper() for x in datasources.keys()]))
    metadata = f"PURL: {purl}\nActive datasources: {active_datasources}\n\n"

    table = get_texttable(no_group=True)

    for datasource, advisories in vulnerabilities.items():
        if not advisories:
            table.add_row([datasource.upper(), "", "", ""])
            continue

        for advisory in advisories:
            table.add_row(formatted_row(datasource, advisory))

    pydoc.pager(metadata + table.draw()) if pagination else click.echo(metadata + table.draw())


NORMALIZED_VERSION_RANGE_BY_DATASOURCE = {
    "deps": NormalizedVersionRanges.from_discrete,
    "github": NormalizedVersionRanges.from_github,
    "gitlab": NormalizedVersionRanges.from_gitlab,
    "oss_index": None,
    "osv": NormalizedVersionRanges.from_discrete,
    "snyk": NormalizedVersionRanges.from_snyk,
    "vulnerablecode": NormalizedVersionRanges.from_discrete,
}


def group_by_cve(vulnerabilities, purl, no_compare):
    grouped_by_cve = {}
    nocve = {}
    noadvisory = {}
    for datasource, advisories in vulnerabilities.items():
        if not advisories:
            if datasource not in noadvisory:
                noadvisory[datasource] = []
            noadvisory[datasource].append(
                {
                    "advisory": None,
                }
            )
        for advisory in advisories:
            cve = next((x for x in advisory.aliases if x.startswith("CVE")), None)
            if not cve:
                if datasource not in nocve:
                    nocve[datasource] = []
                nocve[datasource].append(
                    {
                        "advisory": advisory,
                    }
                )
                continue
            if cve not in grouped_by_cve:
                grouped_by_cve[cve] = {}

            if datasource not in grouped_by_cve[cve]:
                grouped_by_cve[cve][datasource] = []
            grouped_by_cve[cve][datasource].append(
                {
                    "advisory": advisory,
                }
            )
    grouped_by_cve["NOCVE"] = nocve
    grouped_by_cve["NOADVISORY"] = noadvisory
    if not no_compare:
        normalize_version_ranges(grouped_by_cve, purl)
        compare(grouped_by_cve)
    return grouped_by_cve


def normalize_version_ranges(grouped_by_cve, purl):
    package_versions = get_all_versions(purl)

    for cve, value in grouped_by_cve.items():
        if cve in ("NOCVE", "NOADVISORY"):
            continue
        for datasource, resources in value.items():
            for resource in resources:
                advisory = resource["advisory"]
                normalized_affected_versions = []
                normalized_fixed_versions = []
                datasource_normalizer = NORMALIZED_VERSION_RANGE_BY_DATASOURCE.get(datasource)
                if datasource_normalizer and advisory.affected_versions:
                    try:
                        normalized_affected_versions = datasource_normalizer(
                            advisory.affected_versions, purl.type, package_versions
                        )
                    except Exception as err:
                        normalized_affected_versions = [err]

                if advisory.fixed_versions:
                    try:
                        normalized_fixed_versions = NormalizedVersionRanges.from_discrete(
                            advisory.fixed_versions, purl.type, package_versions
                        )
                    except Exception as err:
                        normalized_fixed_versions = [err]

                resource["normalized_affected_versions"] = normalized_affected_versions
                resource["normalized_fixed_versions"] = normalized_fixed_versions


def compare(grouped_by_cve):
    for cve, value in grouped_by_cve.items():
        if cve in ("NOCVE", "NOADVISORY"):
            continue
        sources = list(value.keys())
        board = {source: {} for source in sources}
        """
        A typical board after comparison may look like this.

        board = {
            "github":{
                "snyk": 0,
                "gitlab": 1,
                "deps": 0,
                "vulnerablecode": 1,
                "osv": 1,
                "oss_index": 1,
            },
            "snyk":{
                "github": 0,
                "gitlab": 1,
                "deps": 0,
                "vulnerablecode": 1,
                "osv": 1,
                "oss_index": 1,
            },
            ...
        }
        """
        for datasource, resources in value.items():
            normalized_affected_versions_a = get_item(resources, 0, "normalized_affected_versions")
            normalized_fixed_versions_a = get_item(resources, 0, "normalized_fixed_versions")
            if normalized_fixed_versions_a and normalized_affected_versions_a:
                for source in sources:
                    if (
                        source == datasource
                        or source in board[datasource]
                        or datasource in board[source]
                    ):
                        continue
                    normalized_affected_versions_b = get_item(
                        value, source, 0, "normalized_affected_versions"
                    )
                    normalized_fixed_versions_b = get_item(
                        value, source, 0, "normalized_fixed_versions"
                    )
                    board[datasource][source] = 0
                    board[source][datasource] = 0
                    if (
                        normalized_fixed_versions_a == normalized_fixed_versions_b
                        and normalized_affected_versions_a == normalized_affected_versions_b
                    ):
                        board[datasource][source] = 1
                        board[source][datasource] = 1

        maximum = max([sum(list(table.values())) for table in board.values()])
        datasource_count = len(sources)
        for datasource, table in board.items():
            if maximum == 0:
                # NA if only one advisory else TC aka `Total Collision`.
                value[datasource][0]["score"] = "TC" if datasource_count > 1 else "NA"
                continue
            value[datasource][0]["score"] = (sum(list(table.values())) / maximum) * 100


def prettyprint_group_by_cve(purl, datasources, pagination, no_threading, vers, no_compare):
    vulnerabilities = run_datasources(purl, datasources, no_threading)
    if not vulnerabilities:
        return
    grouped_by_cve = group_by_cve(vulnerabilities, PackageURL.from_string(purl), no_compare)

    active_datasource = ", ".join(sorted([x.upper() for x in datasources.keys()]))
    metadata = f"PURL: {purl}\nActive DataSources: {active_datasource}\n\n"

    table = get_texttable(no_compare=no_compare)

    for cve, value in grouped_by_cve.items():
        for datasource, resources in value.items():
            row = [cve] + formatted_row(datasource, resources[0].get("advisory"))
            if not no_compare:
                row.append(resources[0].get("score", "NA"))

            table.add_row(row)

            if not no_compare and vers and "score" in resources[0]:
                na_affected = get_item(resources, 0, "normalized_affected_versions")
                na_fixed = get_item(resources, 0, "normalized_fixed_versions")
                na_affected = (
                    na_affected.version_ranges
                    if isinstance(na_affected, NormalizedVersionRanges)
                    else na_affected
                )
                na_fixed = (
                    na_fixed.version_ranges
                    if isinstance(na_fixed, NormalizedVersionRanges)
                    else na_fixed
                )
                na_affected = "\n".join([str(i) for i in na_affected])
                na_fixed = "\n".join([str(i) for i in na_fixed])
                table.add_row(["", "", "", na_affected, na_fixed, ""])

    pydoc.pager(metadata + table.draw()) if pagination else click.echo(metadata + table.draw())


def strip_leading_v(version):
    if version.startswith("v"):
        return version[1:]
    return version


def get_texttable(no_group=False, no_compare=False):
    quantum = 100 / 125
    terminal_width = os.get_terminal_size().columns
    line_factor = terminal_width / 100

    column_5x = math.floor(5 * quantum * line_factor)
    column_15x = math.floor(15 * quantum * line_factor)
    column_20x = math.floor(20 * quantum * line_factor)

    table = Texttable()

    if no_group:
        table.set_cols_dtype(["t", "t", "t", "t"])
        table.set_cols_align(["c", "l", "l", "l"])
        table.set_cols_valign(["t", "t", "a", "t"])
        table.set_cols_width([column_20x, column_20x, column_20x, column_20x])
        table.header(["DATASOURCE", "ALIASES", "AFFECTED", "FIXED"])
        return table

    if no_compare:
        table.set_cols_dtype(["a", "a", "a", "a", "a"])
        table.set_cols_align(["l", "l", "l", "l", "l"])
        table.set_cols_valign(["t", "t", "t", "a", "t"])
        table.set_cols_width([column_20x, column_15x, column_20x, column_20x, column_20x])
        table.header(["CVE", "DATASOURCE", "ALIASES", "AFFECTED", "FIXED"])
        return table

    table.set_cols_dtype(["a", "a", "a", "a", "a", "a"])
    table.set_cols_align(["l", "l", "l", "l", "l", "l"])
    table.set_cols_valign(["t", "t", "t", "a", "t", "t"])
    table.set_cols_width([column_20x, column_15x, column_20x, column_20x, column_20x, column_5x])
    table.header(["CVE", "DATASOURCE", "ALIASES", "AFFECTED", "FIXED", "SCORE"])

    return table


def get_all_versions(purl: PackageURL):
    if purl.type not in VERSION_API_CLASSES_BY_PACKAGE_TYPE:
        return

    versionAPI = None
    package_name = None

    if purl.type == "maven":
        package_name = f"{purl.namespace}:{purl.name}"
    if purl.type in ("composer", "golang", "github"):
        package_name = f"{purl.namespace}/{purl.name}"
    if purl.type in ("nuget", "pypi", "gem", "npm", "hex", "deb", "cargo"):
        package_name = purl.name

    versionAPI = VERSION_API_CLASSES_BY_PACKAGE_TYPE.get(purl.type)()
    all_versions = versionAPI.fetch(package_name)

    return [strip_leading_v(package_version.value) for package_version in all_versions]


if __name__ == "__main__":
    handler()

"""
Advanced Usage: vulntotal_cli.py [OPTIONS] [PURL]

  Runs the PURL through all the available datasources and group vulnerability
  by CVEs. Use the special '-' file name to print JSON or YAML results on
  screen/stdout.

Options:
  -l, --list                      Lists all the available DataSources.
  --json FILE                     Write output as pretty-printed JSON to FILE.
  --yaml FILE                     Write output as YAML to FILE.
  -e, --enable                    Enable these datasource/s only.
  -d, --disable                   Disable these datasource/s.
  --ecosystem                     Lists ecosystem supported by active DataSources
  --raw                           List of all the raw response from DataSources.
  --no-threading                  Run DataSources sequentially.
  -p, --pagination                Enable default pagination.
  --no-group                      Don't group by CVE.
  --vers                          Show normalized vers.
  --no-compare                    Do not compare datasource output.
  -h, --help                      Show this message and exit.
"""
