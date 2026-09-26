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
    const chartContainer = document.getElementById(`chart-${id}`);
    if (!chartContainer) return;

    const labels = config.columns[0].slice(1);
    const values = config.columns[1].slice(1);
    const monoColor = config.color || getCssVar("--bulma-link");

    chartContainer.innerHTML = "";

    labels.forEach((label, index) => {
        const row = document.createElement("div");
        row.style.marginBottom = "12px";
        row.style.cursor = "pointer";

        const title = document.createElement("div");
        title.textContent =
            config.full_labels?.[index] || label;

        const bar = document.createElement("div");
        bar.style.height = "28px";
        bar.style.width = `${Math.max(values[index] * 10, 20)}px`;
        bar.style.maxWidth = "100%";
        bar.style.backgroundColor = monoColor;
        bar.style.borderRadius = "4px";
        bar.style.marginTop = "4px";
        bar.textContent = values[index].toLocaleString();
        bar.style.color = "white";
        bar.style.paddingLeft = "8px";
        bar.style.lineHeight = "28px";

        row.appendChild(title);
        row.appendChild(bar);

        row.addEventListener("click", async () => {
            const cweId = label.replace("CWE-", "");

            try {
                const response = await fetch(
                    `/insights/cwe/${cweId}/advisories/`
                );

                if (!response.ok) {
                    throw new Error("Failed to fetch advisories");
                }

                const data = await response.json();

                showCweAdvisories(label, data.advisories);
            } catch (error) {
                console.error("Error loading CWE advisories:", error);
                showCweAdvisories(label, []);
            }
        });

        chartContainer.appendChild(row);
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
            bubble: { maxR: 40 },
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

function showCweAdvisories(cwe, advisories) {
    let modal = document.getElementById("cwe-advisories-modal");

    if (!modal) {
        modal = document.createElement("div");
        modal.id = "cwe-advisories-modal";
        modal.className = "modal";

        modal.innerHTML = `
            <div class="modal-background"></div>
            <div class="modal-card">
                <header class="modal-card-head">
                    <p class="modal-card-title" id="cwe-advisories-title"></p>
                    <button class="delete" aria-label="close"></button>
                </header>

                <section class="modal-card-body" id="cwe-advisories-body">
                </section>
            </div>
        `;

        document.body.appendChild(modal);

        modal.querySelector(".modal-background").addEventListener(
            "click",
            () => modal.classList.remove("is-active")
        );

        modal.querySelector(".delete").addEventListener(
            "click",
            () => modal.classList.remove("is-active")
        );
    }

    document.getElementById("cwe-advisories-title").textContent =
        `${cwe} Advisories`;

    const body = document.getElementById("cwe-advisories-body");

    if (!advisories.length) {
        body.innerHTML = `
            <p class="has-text-grey">
                No advisories found for ${cwe}.
            </p>
        `;
    } else {
        body.innerHTML = `
            <div class="content">
                <p>
                    <strong>${advisories.length}</strong>
                    advisories associated with ${cwe}
                </p>
                <ul>
                    ${advisories.map(advisory => `
                        <li>
                            <a href="${advisory.url}" target="_blank">
                                ${advisory.avid}
                            </a>
                            ${
                                advisory.summary
                                    ? `<p class="has-text-grey">${advisory.summary}</p>`
                                    : ""
                            }
                        </li>
                    `).join("")}
                </ul>
            </div>
        `;
    }

    modal.classList.add("is-active");
}
