//
// Copyright (c) nexB Inc. and others. All rights reserved.
// VulnerableCode is a trademark of nexB Inc.
// SPDX-License-Identifier: Apache-2.0
// See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
// See https://github.com/aboutcode-org/vulnerablecode for support or download.
// See https://aboutcode.org for more information about nexB OSS projects.
//

export const getCssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

const paletteVars = [
    "--bulma-primary",
    "--bulma-link",
    "--bulma-info",
    "--bulma-success",
    "--bulma-warning",
    "--bulma-danger",
    "--bulma-orange",
    "--bulma-purple",
    "--bulma-grey",
    "--bulma-primary-dark",
];

const getPalette = () => paletteVars.map(getCssVar).filter(Boolean);

const getBucketColors = () => [
    getCssVar("--bulma-success"), getCssVar("--bulma-success"), getCssVar("--bulma-success"), getCssVar("--bulma-success"), // 0-3: Success
    getCssVar("--bulma-warning"), getCssVar("--bulma-warning"), getCssVar("--bulma-warning"), // 4-6: Warning
    getCssVar("--bulma-orange"), // 7: Orange
    getCssVar("--bulma-danger"), getCssVar("--bulma-danger") // 8-9: Danger
];

export const formatWholeNumbersOnly = (x) => (Number.isInteger(x) ? x : "");

export const renderers = {
    donut(id, config) {
        const bbConfig = {
            bindto: `#chart-${id}`,
            data: { columns: config.columns, type: "donut", colors: { "Others": "#1b1b1b3a" } },
            color: { pattern: getPalette() },
            legend: { show: true }
        };

        if (config.others_list?.length) {
            bbConfig.tooltip = {
                contents(d, defaultTitle, defaultVal, color) {
                    if (d[0].id !== "Others") return this.internal.getTooltipContent(d, defaultTitle, defaultVal, color);

                    //Customize tooltip to show table for Others
                    const total = config.columns.reduce((sum, col) => sum + col[1], 0);
                    let html = "<table class='bb-tooltip'><tbody><tr><th colspan='2'>Others</th></tr>";
                    config.others_list.forEach(([name, val]) => {
                        html += `<tr><td class='name'>${name}</td><td class='value'>${val.toLocaleString()} (${((val / total) * 100).toFixed(1)}%)</td></tr>`;
                    });
                    return html + "</tbody></table>";
                }
            };
        }
        bb.generate(bbConfig);
    },

    colored_bar(id, config) {
        const monoColor = getCssVar("--bulma-link")
        bb.generate({
            bindto: `#chart-${id}`,
            data: { x: "x", columns: config.columns, type: "bar", color: () => monoColor },
            axis: {
                rotated: true,
                x: { type: "category", label: { text: "CWE", position: "outer-middle" } },
                y: { label: { text: "Advisories", position: "outer-center" }, tick: { format: formatWholeNumbersOnly } }
            },
            tooltip: { format: { title: x => config.full_labels?.[x] || x, value: val => val.toLocaleString() } },
            legend: { show: false }
        });
    },

    scatter(id, config) {
        const [, ...buckets] = config.columns[0];
        const [, ...counts] = config.columns[1];
        const BUCKET_COLORS = getBucketColors();

        const rows = document.getElementById(`chart-${id}-rows`);
        const total = document.getElementById(`chart-${id}-total`);
        const rowTemplate = document.getElementById(`chart-${id}-row-template`);

        if (!rows || !total || !rowTemplate) return;

        const maxCount = Math.max(1, ...counts);
        const frag = document.createDocumentFragment();

        // Build the table rows for each CVSS bucket
        buckets.forEach((bucket, i) => {
            const count = counts[i];
            const clone = rowTemplate.content.cloneNode(true);
            
            // Set bucket label (e.g. "9-10")
            const labelNode = clone.querySelector('.sev-bucket-label');
            labelNode.textContent = bucket;
            
            // Calculate size and paint the colored bubble
            const barNode = clone.querySelector('.sev-bucket-bar');
            const barWidth = Math.max(2, (count / maxCount) * 140);
            barNode.style.width = `${barWidth}px`;
            barNode.style.background = BUCKET_COLORS[i];

            // Display the vulnerability count on tooltip
            const countNode = clone.querySelector('.sev-td-count');
            countNode.title = `CVSS ${bucket}: ${count.toLocaleString()}`;
            countNode.innerHTML = count.toLocaleString();
            
            frag.appendChild(clone);
        });

        // Render the completed table to the DOM
        rows.innerHTML = ""; 
        rows.appendChild(frag);       
        const sumOfCounts = counts.reduce((sum, count) => sum + count, 0);
        total.textContent = sumOfCounts.toLocaleString();

        bb.generate({
            bindto: `#chart-${id}-bb`,
            data: {
                x: "x", columns: config.columns, type: "bubble",
                color: (defaultColor, dataPoint) => dataPoint.x !== undefined ? getBucketColors()[dataPoint.x] || defaultColor : defaultColor, 
                labels: false
            },
            bubble: { maxR: 45 },
            axis: { 
                x: { 
                    type: "category", 
                    tick: { multiline: false },
                    label: { text: "CVSS Score Range", position: "outer-center" }
                }, 
                y: { show: false, min: 0, max: maxCount * 1.2, padding: { top: 70, bottom: 0 } } 
            },
            grid: { x: { show: true } }, 
            legend: { show: false },
            tooltip: { 
                format: { 
                    title: x => `CVSS ${buckets[x]}`, 
                    name: () => "Advisories", 
                    value: val => val.toLocaleString() 
                } 
            }
        });
    }
};
