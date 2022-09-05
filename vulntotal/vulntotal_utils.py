#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnTotal software is licensed under the Apache License version 2.0.
# Data generated with VulnTotal require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnTotal or any VulnTotal
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnTotal and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnTotal should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnTotal is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import operator


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
    if constraint.startswith(("<=", ">=", "==", "!=")):
        return constraint[:2], constraint[2:]

    if constraint.startswith(("<", ">", "=", "[", "]", "(", ")")):
        return constraint[0], constraint[1:]

    if constraint.endswith(("[", "]", "(", ")")):
        return constraint[-1], constraint[:-1]


def github_constraints_satisfied(github_constrain, version):
    gh_constraints = github_constrain.strip().replace(" ", "")
    constraints = gh_constraints.split(",")
    for constraint in constraints:
        gh_comparator, gh_version = parse_constraint(constraint)
        if not gh_version:
            continue
        # TODO: Replace the GenericVersion with ecosystem specific from univers
        if not compare(GenericVersion(version), gh_comparator, GenericVersion(gh_version)):
            return False
    return True


def snky_constraints_satisfied(snyk_constrain, version):
    snyk_constraints = snyk_constrain.strip().replace(" ", "")
    constraints = snyk_constraints.split(",")
    for constraint in constraints:
        snyk_comparator, snyk_version = parse_constraint(constraint)
        if not snyk_version:
            continue
        # TODO: Replace the GenericVersion with ecosystem specific from univers or maybe not if snyk is normalizing versions to semver
        if not compare(GenericVersion(version), snyk_comparator, GenericVersion(snyk_version)):
            return False
    return True


def gitlab_constraints_satisfied(gitlab_constrain, version):
    gitlab_constraints = gitlab_constrain.strip()
    constraints = gitlab_constraints.split("||")

    for constraint in constraints:
        is_constraint_satisfied = True

        for subcontraint in constraint.strip().split(" "):

            gitlab_comparator, gitlab_version = parse_constraint(subcontraint.strip())
            if not gitlab_version:
                continue
            # TODO: Replace the GenericVersion with ecosystem specific from univers
            if not compare(
                GenericVersion(version), gitlab_comparator, GenericVersion(gitlab_version)
            ):
                is_constraint_satisfied = False
                break

        if is_constraint_satisfied:
            return True
