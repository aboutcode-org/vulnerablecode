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
    total_advisories: "Total Advisories",
    advisories_without_packages: "Advisories without a Package",
    advisories_with_packages: "Advisories with a Package",
    advisories_without_ghost_packages: "Advisories without a Ghost Package",
    advisories_with_ghost_packages: "Advisories with a Ghost Package",
    advisories_without_exploits: "Advisories without an Exploit",
    advisories_with_exploitdb: "Advisories with Exploit-DB",
    advisories_with_metasploit: "Advisories with Metasploit",
    advisories_with_kev: "Advisories with KEV",
    advisories_with_exploits: "Advisories with an Exploit",
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
            format: {
                title: (x) => `${config.x_categories[x]} (Total: ${totals?.[x + 1]?.toLocaleString()})`,
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
