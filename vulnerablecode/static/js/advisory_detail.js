//
// Copyright (c) nexB Inc. and others. All rights reserved.
// VulnerableCode is a trademark of nexB Inc.
// SPDX-License-Identifier: Apache-2.0
// See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
// See https://github.com/aboutcode-org/vulnerablecode for support or download.
// See https://aboutcode.org for more information about nexB OSS projects.
//

(function () {
    let epssChartInstance = null;
    
    const [btnChart, btnTable, chartContainer, tableContainer] = 
        ["btn-load-epss-chart", "btn-load-epss-table", "epss-chart-container", "epss-history-table-container"]
        .map(id => document.getElementById(id));

    const getHistoryData = () => JSON.parse(document.getElementById('epss-history-data')?.textContent || "[]");
    const toggleDisplay = (el) => el.style.display = el.style.display === "none" ? "block" : "none";

    const updateBtn = (btn, container) => {
        if (!btn || !container) return;
        const isHidden = container.style.display === "none";
        btn.textContent = btn.textContent.replace(isHidden ? "Hide" : "See", isHidden ? "See" : "Hide");
    };

    function renderChart() {
        const history = getHistoryData();
        if (!history.length) return;

        toggleDisplay(chartContainer);
        updateBtn(btnChart, chartContainer);
        
        if (chartContainer.style.display === "none" || epssChartInstance) return;

        try {
            epssChartInstance = bb.generate({
                bindto: "#epss-chart",
                size: { height: 260 }, padding: { right: 25 },
                data: {
                    x: "Date", xFormat: "%Y-%m-%d",
                    columns: [
                        ["Date", ...history.map(h => h.published_at || "")],
                        ["Score", ...history.map(h => h.score === null ? null : parseFloat(h.score))],
                        ["Percentile", ...history.map(h => h.percentile === null ? null : parseFloat(h.percentile))],
                    ],
                    type: "line", colors: { Score: "#df25e6ff", Percentile: "#00d1b2" },
                },
                //Handles missing dates
                line: { connectNull: false },
                axis: {
                    x: { type: "timeseries", tick: { format: "%b %d", count: Math.min(history.length, 6), fit: true } },
                    y: { min: 0, max: 1, padding: { top: 10, bottom: 0 }, tick: { format: v => v.toFixed(4) } },
                },
                point: { r: 3 }, legend: { show: true },
                tooltip: {
                    format: {
                        title: d => d instanceof Date ? `${d.toLocaleString('en-us', {month: 'short'})} ${String(d.getDate()).padStart(2, '0')}, ${d.getFullYear()}` : String(d),
                        value: v => v.toFixed(5),
                    },
                },
            });
        } catch (e) { console.error("[epss-chart]", e); }
    }

    btnChart?.addEventListener("click", renderChart);
    btnTable?.addEventListener("click", () => {
        toggleDisplay(tableContainer);
        updateBtn(btnTable, tableContainer);
    });

    updateBtn(btnChart, chartContainer);
    updateBtn(btnTable, tableContainer);
})();
