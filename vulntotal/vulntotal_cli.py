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
import pydoc

import click

# TODO: use saneyaml
import yaml
from packageurl import PackageURL
from texttable import Texttable

from vulntotal.datasources import DATASOURCE_REGISTRY
from vulntotal.validator import VendorData


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

# hidden debug options
@click.option(
    "-l",
    "--list",
    "list_source",
    is_flag=True,
    multiple=False,
    required=False,
    help="List available datasources.",
)
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
    help="Report the raw responses from each datasource. Used for debugging. Used for debugging.",
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
        write_json_output(purl, active_datasource, json_output, no_threading)

    elif yaml_output:
        write_yaml_output(purl, active_datasource, yaml_output, no_threading)

    elif no_group:
        prettyprint(purl, active_datasource, pagination, no_threading)

    elif purl:
        prettyprint_group_by_cve(purl, active_datasource, pagination, no_threading)


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


class VendorDataEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, VendorData):
            return obj.to_dict()
        return json.JSONEncoder.default(self, obj)


def write_json_output(purl, datasources, json_output, no_threading):
    vulnerabilities = run_datasources(purl, datasources, no_threading)
    return json.dump(vulnerabilities, json_output, cls=VendorDataEncoder, indent=2)


def noop(self, *args, **kw):
    pass


yaml.emitter.Emitter.process_tag = noop


def write_yaml_output(purl, datasources, yaml_output, no_threading):
    vulnerabilities = run_datasources(purl, datasources, no_threading)
    return yaml.dump(vulnerabilities, yaml_output, default_flow_style=False, indent=2)


def prettyprint(purl, datasources, pagination, no_threading):
    vulnerabilities = run_datasources(purl, datasources, no_threading)
    if not vulnerabilities:
        return

    active_datasources = ", ".join(sorted([x.upper() for x in datasources.keys()]))
    metadata = f"PURL: {purl}\nActive datasources: {active_datasources}\n\n"

    table = Texttable()
    table.set_cols_dtype(["t", "t", "t", "t"])
    table.set_cols_align(["c", "l", "l", "l"])
    table.set_cols_valign(["t", "t", "a", "t"])
    table.header(["DATASOURCE", "ALIASES", "AFFECTED", "FIXED"])

    for datasource, advisories in vulnerabilities.items():
        if not advisories:
            table.add_row([datasource.upper(), "", "", ""])
            continue

        for advisory in advisories:
            table.add_row(formatted_row(datasource, advisory))

    pydoc.pager(metadata + table.draw()) if pagination else click.echo(metadata + table.draw())


def group_by_cve(vulnerabilities):
    grouped_by_cve = {}
    no_cve = []
    no_advisory = []
    for datasource, advisories in vulnerabilities.items():
        if not advisories:
            no_advisory.append([datasource.upper(), "", "", ""])

        for advisory in advisories:
            cve = next((x for x in advisory.aliases if x.startswith("CVE")), None)
            if not cve:
                no_cve.append(formatted_row(datasource, advisory))
                continue
            if cve not in grouped_by_cve:
                grouped_by_cve[cve] = []
            grouped_by_cve[cve].append(formatted_row(datasource, advisory))
    grouped_by_cve["NOCVE"] = no_cve
    grouped_by_cve["NOADVISORY"] = no_advisory
    return grouped_by_cve


def prettyprint_group_by_cve(purl, datasources, pagination, no_threading):
    vulnerabilities = run_datasources(purl, datasources, no_threading)
    if not vulnerabilities:
        return
    grouped_by_cve = group_by_cve(vulnerabilities)

    active_datasource = ", ".join(sorted([x.upper() for x in datasources.keys()]))
    metadata = f"PURL: {purl}\nActive DataSources: {active_datasource}\n\n"

    table = Texttable()
    table.set_cols_dtype(["a", "a", "a", "a", "a"])
    table.set_cols_align(["l", "l", "l", "l", "l"])
    table.set_cols_valign(["t", "t", "t", "a", "t"])
    table.header(["CVE", "DATASOURCE", "ALIASES", "AFFECTED", "FIXED"])

    for cve, advisories in grouped_by_cve.items():
        for count, advisory in enumerate(advisories):
            table.add_row([cve] + advisory)

    pydoc.pager(metadata + table.draw()) if pagination else click.echo(metadata + table.draw())


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
  -h, --help                      Show this message and exit.
"""
