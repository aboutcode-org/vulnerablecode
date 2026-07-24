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
    if (e.detail.panelId !== "importer_panel") return;
    const { snapshotData } = e.detail;

    ["importer-empty-pkg-bar", "importer-exploit-bar"].forEach(id => {
        initDropdownChart(id, snapshotData[id], "Top 5 Importers");
    });
});
