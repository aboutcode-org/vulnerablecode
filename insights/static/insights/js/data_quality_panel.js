//
// Copyright (c) nexB Inc. and others. All rights reserved.
// VulnerableCode is a trademark of nexB Inc.
// SPDX-License-Identifier: Apache-2.0
// See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
// See https://github.com/aboutcode-org/vulnerablecode for support or download.
// See https://aboutcode.org for more information about nexB OSS projects.
//

import { initDropdownChart } from './core.js';

document.addEventListener('insightsDataLoaded', (e) => {
    if (e.detail.panelId !== "data_quality_panel") return;

    const { snapshotData } = e.detail;
    if (!snapshotData) return;

    initDropdownChart("dq-issue-type-bar", snapshotData["dq-issue-type-bar"], "All Datasources");
    initDropdownChart("dq-importer-contribution-donut", snapshotData["dq-importer-contribution-donut"], "All Issue Types");
    initDropdownChart("dq-resolution-timeline", snapshotData["dq-resolution-timeline"], "All Importers");
});
