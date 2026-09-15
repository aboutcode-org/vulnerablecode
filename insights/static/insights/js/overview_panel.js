//
// Copyright (c) nexB Inc. and others. All rights reserved.
// VulnerableCode is a trademark of nexB Inc.
// SPDX-License-Identifier: Apache-2.0
// See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
// See https://github.com/aboutcode-org/vulnerablecode for support or download.
// See https://aboutcode.org for more information about nexB OSS projects.
//

import { renderChartWithData } from './core.js';

function formatDelta(delta) {
    if (delta > 0) return `<span class="delta-positive">+${delta.toLocaleString()}</span> from last snapshot`;
    if (delta < 0) return `<span class="delta-negative">${delta.toLocaleString()}</span> from last snapshot`;
    return "No change from last snapshot";
}

document.addEventListener('insightsDataLoaded', (e) => {
    if (e.detail.panelId !== "overview_panel") return;

    const snapshotData = e.detail.snapshotData;
    if (!snapshotData || !snapshotData["overview-stats"]) return;

    const overviewData = snapshotData["overview-stats"];

    const kpis = overviewData.kpis;
    if (kpis) {
        document.getElementById("kpi-total-advisories").textContent = kpis.total_advisories.toLocaleString();
        document.getElementById("kpi-delta-advisories").innerHTML = formatDelta(kpis.delta_advisories);
        
        document.getElementById("kpi-total-packages").textContent = kpis.total_packages.toLocaleString();
        document.getElementById("kpi-delta-packages").innerHTML = formatDelta(kpis.delta_packages);

        document.getElementById("kpi-total-sources").textContent = kpis.total_data_sources.toLocaleString();
        document.getElementById("kpi-delta-sources").innerHTML = formatDelta(kpis.delta_data_sources);
    }

    renderChartWithData("overview-historical", "global", snapshotData["overview-historical"]);
    renderChartWithData("overview-cross-validation", "global", snapshotData["overview-cross-validation"]);
    renderChartWithData("overview-growth-trend", "global", snapshotData["overview-growth-trend"]);
});
