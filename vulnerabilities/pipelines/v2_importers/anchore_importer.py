#
# Copyright (c) nexB Inc. and others. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

import logging
from typing import Iterable

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2

logger = logging.getLogger(__name__)


class AnchoreImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Importer for https://github.com/anchore/nvd-data-overrides
    """

    pipeline_id = "anchore_importer_v2"
    datasource_id = "anchore"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/anchore/nvd-data-overrides/blob/main/LICENSE"
