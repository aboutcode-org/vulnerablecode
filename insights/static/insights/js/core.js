//
// Copyright (c) nexB Inc. and others. All rights reserved.
// VulnerableCode is a trademark of nexB Inc.
// SPDX-License-Identifier: Apache-2.0
// See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
// See https://github.com/aboutcode-org/vulnerablecode for support or download.
// See https://aboutcode.org for more information about nexB OSS projects.
//

import { renderers } from './renderers.js';

export function renderChartWithData(chartId, key, chartDataMap = {}) {
    // Handle dropdown charts with key
    const chartData = key && chartDataMap[key] ? chartDataMap[key] : chartDataMap;
    const chartContainer = document.getElementById(`chart-${chartId}`);
    if (!chartContainer) return;

    if (!chartData?.columns?.length) {
        chartContainer.innerHTML = "<p class='has-text-grey has-text-centered mt-5'>No data available.</p>";
        return;
    }

    const type = chartContainer.dataset.chartType;
    if (renderers[type]) renderers[type](chartId, chartData);
}

export function initDropdownChart(chartId, chartData, defaultLabel) {
    const chartContainer = document.getElementById(`chart-${chartId}`);
    if (!chartData || !chartContainer || chartContainer.previousElementSibling?.classList.contains("chart-dropdown-wrapper")) return;

    const options = Object.keys(chartData).filter(k => k !== "global");
    if (options.length) {
        chartContainer.insertAdjacentHTML("beforebegin", `
            <div class="chart-dropdown-wrapper mb-3">
                <div class="select is-small">
                    <select>
                        <option value="global">${defaultLabel}</option>
                        ${options.map(o => `<option value="${o}">${o}</option>`).join("")}
                    </select>
                </div>
            </div>
        `);
        chartContainer.previousElementSibling.querySelector("select").addEventListener("change", ev =>
            renderChartWithData(chartId, ev.target.value, chartData)
        );
    }
    renderChartWithData(chartId, "global", chartData);
}

export function initDashboard() {
    const layout = document.querySelector(".insights-layout");
    if (!layout) return;
    const data = JSON.parse(document.getElementById("insights-snapshot-data")?.textContent || "{}");
    document.dispatchEvent(new CustomEvent('insightsDataLoaded', { detail: { data, snapshotData: data.snapshot_data || {}, panelId: layout.dataset.panel } }));
}

setTimeout(initDashboard, 0);
