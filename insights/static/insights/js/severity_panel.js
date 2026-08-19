//
// Copyright (c) nexB Inc. and others. All rights reserved.
// VulnerableCode is a trademark of nexB Inc.
// SPDX-License-Identifier: Apache-2.0
// See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
// See https://github.com/aboutcode-org/vulnerablecode for support or download.
// See https://aboutcode.org for more information about nexB OSS projects.
//

import { renderChartWithData } from './core.js';

document.addEventListener('insightsDataLoaded', (e) => {
    if (e.detail.panelId !== "severity_panel") return;

    const chartId = "severity-scatter-plot";
    const searchData = document.getElementById("chart-search-data")?.textContent;

    if (searchData) {
        renderChartWithData(chartId, null, JSON.parse(searchData));
    } else {
        renderChartWithData(chartId, "global", e.detail.snapshotData[chartId]);
    }
});
