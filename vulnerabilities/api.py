#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from rest_framework import serializers
from rest_framework import status
from rest_framework import viewsets
from rest_framework.response import Response

from packageurl import PackageURL

from vulnerabilities.models import Package
from vulnerabilities.models import PackageReference
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference


class PackageReferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = PackageReference
        fields = [
            'repository',
            'platform',
            'name',
            'version',
        ]


class VulnerabilityReferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityReference
        fields = [
            'source',
            'reference_id',
            'url',
        ]


class VulnerabilitySerializer(serializers.ModelSerializer):
    references = VulnerabilityReferenceSerializer(source='vulnerabilityreference_set', many=True)

    class Meta:
        model = Vulnerability
        fields = [
            'summary',
            'cvss',
            'references',
        ]


class PackageSerializer(serializers.ModelSerializer):
    vulnerabilities = VulnerabilitySerializer(many=True)
    references = PackageReferenceSerializer(source='packagereference_set', many=True)

    class Meta:
        model = Package
        fields = [
            'name',
            'version',
            'package_url',
            'vulnerabilities',
            'references',
        ]


class PackageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    filterset_fields = ('name', 'version')

    def filter_queryset(self, qs):
        purl = self.request.query_params.get('package_url')
        if not purl:
            return super().filter_queryset(qs)

        try:
            purl = PackageURL.from_string(purl)
        except ValueError as ve:
            raise serializers.ValidationError(
                detail={'error': f'"{purl}" is not a valid Package URL: {ve}'},
            )

        # Remove "qualifiers" here because it is stored as one string in the model.
        # For example, a row in the database could have the "qualifiers" column
        # stored as "foo=bar&spam=eggs". If an API request contains a PURL with
        # "spam=eggs&foo=bar", the DB query would not include that row.
        attrs = {k: v for k, v in purl.to_dict().items() if v and k != 'qualifiers'}

        # TODO
        # Since we are filtering on all the Package URL fields except "qualifiers",
        # we'll eventually need database indices on them.
        return self.queryset.filter(**attrs)
