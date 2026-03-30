#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.db import transaction


@transaction.atomic
def delete_and_save_advisory_set(groups, package, relation=None):
    from vulnerabilities.models import AdvisorySet
    from vulnerabilities.models import AdvisorySetMember

    AdvisorySet.objects.filter(package=package, relation_type=relation).delete()

    membership_to_create = []

    for identifiers, primary, secondary in groups:

        advisory_set = AdvisorySet.objects.create(
            package=package,
            relation_type=relation,
            primary_advisory=primary,
        )

        advisory_set.aliases.add(*identifiers)
        advisory_set.save()

        membership_to_create.append(
            AdvisorySetMember(
                advisory_set=advisory_set,
                advisory=primary,
                is_primary=True,
            )
        )

        for adv in secondary:
            membership_to_create.append(
                AdvisorySetMember(
                    advisory_set=advisory_set,
                    advisory=adv,
                    is_primary=False,
                )
            )

    AdvisorySetMember.objects.bulk_create(membership_to_create)
