//
// Copyright (c) nexB Inc. and others. All rights reserved.
// VulnerableCode is a trademark of nexB Inc.
// SPDX-License-Identifier: Apache-2.0
// See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
// See https://github.com/aboutcode-org/vulnerablecode for support or download.
// See https://aboutcode.org for more information about nexB OSS projects.
//

import { renderChartWithData, initDropdownChart } from './core.js';

document.addEventListener('insightsDataLoaded', (e) => {
    if (e.detail.panelId !== "package_panel") return;

    const { snapshotData } = e.detail;
    const searchData = document.getElementById("chart-search-data")?.textContent;
    const parsedSearch = searchData ? JSON.parse(searchData) : null;

    initDropdownChart("pkg-name-bar", snapshotData["pkg-name-bar"], "All Packages");

    renderChartWithData(
        "pkg-cwe-bar",
        parsedSearch ? null : "global",
        parsedSearch?.["pkg-cwe-bar"] || snapshotData["pkg-cwe-bar"]
    );

    renderChartWithData("pkg-dist-donut", "global", snapshotData["pkg-dist-donut"]);
});
