//
// Copyright (c) nexB Inc. and others. All rights reserved.
// VulnerableCode is a trademark of nexB Inc.
// SPDX-License-Identifier: Apache-2.0
// See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
// See https://github.com/aboutcode-org/vulnerablecode for support or download.
// See https://aboutcode.org for more information about nexB OSS projects.
//

import { initDropdownChart } from './core.js';
import { formatWholeNumbersOnly, getCssVar, renderers } from './renderers.js';

const names = {
    advisories_with_packages: "with a PURL",
    advisories_without_packages: "without a PURL",
    advisories_without_ghost_packages: "with an existing PURL",
    advisories_with_ghost_packages: "with a non-existing PURL",
    advisories_with_exploits: "with an Exploit",
    advisories_without_exploits: "without an Exploit",
    advisories_with_exploitdb: "with a Exploit-DB exploit",
    advisories_with_metasploit: "with a Metasploit exploit",
    advisories_with_kev: "with a KEV",
};

function renderImporterBar(id, config) {
    // Get the total count of the importer from config.columns
    const totals = config.columns.find((c) => c[0] === "total_advisories");

    bb.generate({
        bindto: `#chart-${id}`,
        data: {
            x: "x",
            columns: [["x", ...config.x_categories], ...config.columns],
            type: "bar",
            order: null,
            hide: ["total_advisories"],
            colors: {
                advisories_with_packages: getCssVar("--bulma-primary"),
                advisories_without_packages: getCssVar("--bulma-danger"),
                advisories_with_exploits: getCssVar("--bulma-primary"),
                advisories_without_exploits: getCssVar("--bulma-danger"),
                advisories_with_kev: getCssVar("--bulma-warning"),
                advisories_with_metasploit: getCssVar("--bulma-purple"),
                advisories_with_exploitdb: getCssVar("--bulma-link"),
                advisories_with_ghost_packages: getCssVar("--bulma-orange"),
                advisories_without_ghost_packages: getCssVar("--bulma-primary-dark"),
            },
            names,
            groups: config.groups,
        },
        axis: {
            rotated: true,
            x: { type: "category" },
            y: { tick: { format: formatWholeNumbersOnly } },
        },
        bar: { width: { ratio: 0.8 } },
        tooltip: {
            grouped: true,
            order: (a, b) => {
                //Keep a stable order of rows 
                const cols = config.columns.map(c => c[0]);
                return cols.indexOf(a.id) - cols.indexOf(b.id);
            },
            format: {
                title: (x) => `Advisories from ${config.x_categories[x]} (Total: ${totals?.[x + 1]?.toLocaleString()})`,
                value: (val) => val.toLocaleString(),
            },
        },
        legend: {
            show: true,
            hide: ["total_advisories"],
        },
    });
}

renderers.importer_bar = renderImporterBar;

document.addEventListener('insightsDataLoaded', (e) => {
    if (e.detail.panelId !== "importer_panel") return;
    const { snapshotData } = e.detail;

    ["importer-empty-pkg-bar", "importer-exploit-bar"].forEach(id => {
        initDropdownChart(id, snapshotData[id], "Top 5 Importers");
    });
});
