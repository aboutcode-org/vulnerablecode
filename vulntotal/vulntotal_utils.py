#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import operator
from typing import Union


class GenericVersion:
    def __init__(self, version):
        self.value = version.replace(" ", "").lstrip("v")

        self.decomposed = tuple(
            [int(com) if com.isnumeric() else com for com in self.value.split(".")]
        )

    def __str__(self):
        return str(self.value)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.value.__eq__(other.value)

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        for i, j in zip(self.decomposed, other.decomposed):
            if not isinstance(i, type(j)):
                continue
            if i.__gt__(j):
                return False
        return True

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.__lt__(other) or self.__eq__(other)


def compare(version, package_comparator, package_version):
    operator_comparator = {
        "<": operator.lt,
        ">": operator.gt,
        "=": operator.eq,
        "<=": operator.le,
        ">=": operator.ge,
        "==": operator.eq,
        "!=": operator.ne,
        ")": operator.lt,
        "]": operator.le,
        "(": operator.gt,
        "[": operator.ge,
    }
    compare = operator_comparator[package_comparator]
    return compare(version, package_version)


def parse_constraint(constraint):
    """
    Return operator and version from a constraint
    For example:
    >>> assert parse_constraint(">=7.0.0") == ('>=', '7.0.0')
    >>> assert parse_constraint("=7.0.0") == ('=', '7.0.0')
    >>> assert parse_constraint("[3.0.0") == ('[', '3.0.0')
    >>> assert parse_constraint("3.1.25]") == (']', '3.1.25')
    """
    if constraint.startswith(("<=", ">=", "==", "!=")):
        return constraint[:2], constraint[2:]

    if constraint.startswith(("<", ">", "=", "[", "(")):
        return constraint[0], constraint[1:]

    if constraint.endswith(("]", ")")):
        return constraint[-1], constraint[:-1]


def github_constraints_satisfied(github_constrain, version):
    """
    Return True or False depending on whether the given version satisfies the github constraint
    For example:
    >>> assert github_constraints_satisfied(">= 7.0.0, <= 7.6.57", "7.1.1") == True
    >>> assert github_constraints_satisfied(">= 10.4.0, <= 10.4.1", "10.6.0") == False
    """
    gh_constraints = github_constrain.strip().replace(" ", "")
    constraints = gh_constraints.split(",")
    for constraint in constraints:
        gh_comparator, gh_version = parse_constraint(constraint)
        if not gh_version:
            continue
        if not compare(GenericVersion(version), gh_comparator, GenericVersion(gh_version)):
            return False
    return True


def snky_constraints_satisfied(snyk_constrain, version):
    """
    Return True or False depending on whether the given version satisfies the snyk constraint
    For example:
    >>> assert snky_constraints_satisfied(">=4.0.0, <4.0.10.16", "4.0.10.15") == True
    >>> assert snky_constraints_satisfied(" >=4.1.0, <4.4.15.7", "4.0.10.15") == False
    >>> assert snky_constraints_satisfied("[3.0.0,3.1.25)", "3.0.2") == True
    """
    snyk_constraints = snyk_constrain.strip().replace(" ", "")
    constraints = snyk_constraints.split(",")
    for constraint in constraints:
        snyk_comparator, snyk_version = parse_constraint(constraint)
        if not snyk_version:
            continue
        if not compare(GenericVersion(version), snyk_comparator, GenericVersion(snyk_version)):
            return False
    return True


def gitlab_constraints_satisfied(gitlab_constrain, version):
    """
    Return True or False depending on whether the given version satisfies the gitlab constraint
    For example:
    >>> assert gitlab_constraints_satisfied("[7.0.0,7.0.11),[7.2.0,7.2.4)", "7.2.1") == True
    >>> assert gitlab_constraints_satisfied("[7.0.0,7.0.11),[7.2.0,7.2.4)", "8.2.1") == False
    >>> assert gitlab_constraints_satisfied( ">=4.0,<4.3||>=5.0,<5.2", "5.4") == False
    >>> assert gitlab_constraints_satisfied( ">=0.19.0 <0.30.0", "0.24") == True
    >>> assert gitlab_constraints_satisfied( ">=1.5,<1.5.2", "2.2") == False
    """

    gitlab_constraints = gitlab_constrain.strip()
    if gitlab_constraints.startswith(("[", "(")):
        # transform "[7.0.0,7.0.11),[7.2.0,7.2.4)" -> [ "[7.0.0,7.0.11)", "[7.2.0,7.2.4)" ]
        splitted = gitlab_constraints.split(",")
        constraints = [f"{a},{b}" for a, b in zip(splitted[::2], splitted[1::2])]
        delimiter = ","

    else:
        # transform ">=4.0,<4.3||>=5.0,<5.2" -> [ ">=4.0,<4.3", ">=5.0,<5.2" ]
        # transform ">=0.19.0 <0.30.0" -> [ ">=0.19.0 <0.30.0" ]
        # transform ">=1.5,<1.5.2" -> [ ">=1.5,<1.5.2" ]
        delimiter = "," if "," in gitlab_constraints else " "
        constraints = gitlab_constraints.split("||")

    for constraint in constraints:
        is_constraint_satisfied = True
        for subcontraint in constraint.strip().split(delimiter):
            if not subcontraint:
                continue
            gitlab_comparator, gitlab_version = parse_constraint(subcontraint.strip())
            if not gitlab_version:
                continue
            if not compare(
                GenericVersion(version), gitlab_comparator, GenericVersion(gitlab_version)
            ):
                is_constraint_satisfied = False
                break

        if is_constraint_satisfied:
            return True
    return False


def get_item(entity: Union[dict, list], *attributes):
    """
    Return `item` by going through all the `attributes` present in the `dictionary/list`

    Do a DFS for the `item` in the `dictionary/list` by traversing the `attributes`
    and return None if can not traverse through the `attributes`
    For example:
    >>> get_item({'a': {'b': {'c': 'd'}}}, 'a', 'b', 'e')
    Traceback (most recent call last):
        ...
    KeyError: "Missing attribute e in {'c': 'd'}"
    >>> assert get_item({'a': {'b': {'c': 'd'}}}, 'a', 'b', 'c') == 'd'
    >>> assert get_item({'a': [{'b': {'c': 'd'}}]}, 'a', 0, 'b') == {'c': 'd'}
    >>> assert get_item(['b', ['c', ['d']]], 1, 1, 0) == 'd'
    """
    for attribute in attributes:
        if not entity:
            return
        if not isinstance(entity, (dict, list)):
            raise TypeError(f"Entity must be of type `dict` or `list` not {type(entity)}")
        if isinstance(entity, dict) and attribute not in entity:
            raise KeyError(f"Missing attribute {attribute} in {entity}")
        if isinstance(entity, list) and not isinstance(attribute, int):
            raise TypeError(f"List indices must be integers not {type(attribute)}")
        if isinstance(entity, list) and len(entity) <= attribute:
            raise IndexError(f"Index {attribute} out of range for {entity}")

        entity = entity[attribute]
    return entity
