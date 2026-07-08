const CVSS30_FIELDS = {
    "Base Score Metrics": {
        "AV": { "name": "Attack Vector", "code": "AV", "required":true, "options": [{"name": "Network", "code": "N"}, {"name": "Adjacent Network", "code": "A"}, {"name": "Local", "code": "L"}, {"name": "Physical", "code": "P"}] },
        "AC": { "name": "Attack Complexity", "code": "AC", "required":true, "options": [{"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "PR": { "name": "Privileges Required", "code": "PR", "required":true, "options": [{"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "UI": { "name": "User Interaction", "code": "UI", "required":true, "options": [{"name": "None", "code": "N"}, {"name": "Required", "code": "R"}] },
        "S": { "name": "Scope", "code": "S", "required":true, "options": [{"name": "Unchanged", "code": "U"}, {"name": "Changed", "code": "C"}] },
        "C": { "name": "Confidentiality Impact", "code": "C", "required":true, "options": [{"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "I": { "name": "Integrity Impact", "code": "I", "required":true, "options": [{"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "A": { "name": "Availability Impact", "code": "A", "required":true, "options": [{"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] }
    },
    "Temporal Score Metrics": {
        "E": { "name": "Exploit Code Maturity", "code": "E", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Unproven that exploit exists", "code": "U"}, {"name": "Proof of concept code", "code": "P"}, {"name": "Functional exploit exists", "code": "F"}, {"name": "High", "code": "H"}] },
        "RL": { "name": "Remediation Level", "code": "RL", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Official fix", "code": "O"}, {"name": "Temporary fix", "code": "T"}, {"name": "Workaround", "code": "W"}, {"name": "Unavailable", "code": "U"}] },
        "RC": { "name": "Report Confidence", "code": "RC", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Unknown", "code": "U"}, {"name": "Reasonable", "code": "R"}, {"name": "Confirmed", "code": "C"}] }
    },
    "Environmental Score Metrics": {
        "MAV": { "name": "Modified Attack Vector", "code": "MAV", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Network", "code": "N"}, {"name": "Adjacent Network", "code": "A"}, {"name": "Local", "code": "L"}, {"name": "Physical", "code": "P"}] },
        "MAC": { "name": "Modified Attack Complexity", "code": "MAC", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "MPR": { "name": "Modified Privileges Required", "code": "MPR", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "MUI": { "name": "Modified User Interaction", "code": "MUI", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "None", "code": "N"}, {"name": "Required", "code": "R"}] },
        "MS": { "name": "Modified Scope", "code": "MS", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Unchanged", "code": "U"}, {"name": "Changed", "code": "C"}] },
        "MC": { "name": "Modified Confidentiality Impact", "code": "MC", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "MI": { "name": "Modified Integrity Impact", "code": "MI", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "MA": { "name": "Modified Availability Impact", "code": "MA", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "CR": { "name": "Confidentiality Requirement", "code": "CR", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Low", "code": "L"}, {"name": "Medium", "code": "M"}, {"name": "High", "code": "H"}] },
        "IR": { "name": "Integrity Requirement", "code": "IR", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Low", "code": "L"}, {"name": "Medium", "code": "M"}, {"name": "High", "code": "H"}] },
        "AR": { "name": "Availability Requirement", "code": "AR", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Low", "code": "L"}, {"name": "Medium", "code": "M"}, {"name": "High", "code": "H"}] }
    }
};

const CVSS31_FIELDS = CVSS30_FIELDS;

const CVSS40_FIELDS = {
    "Base Score Metrics": {
        "AV": { "name": "Attack Vector", "code": "AV", "required":true, "options": [{"name": "Network", "code": "N"}, {"name": "Adjacent", "code": "A"}, {"name": "Local", "code": "L"}, {"name": "Physical", "code": "P"}] },
        "AC": { "name": "Attack Complexity", "code": "AC", "required":true, "options": [{"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "AT": { "name": "Attack Requirements", "code": "AT", "required":true, "options": [{"name": "None", "code": "N"}, {"name": "Present", "code": "P"}] },
        "PR": { "name": "Privileges Required", "code": "PR", "required":true, "options": [{"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "UI": { "name": "User Interaction", "code": "UI", "required":true, "options": [{"name": "None", "code": "N"}, {"name": "Passive", "code": "P"}, {"name": "Active", "code": "A"}] },
        "VC": { "name": "Vulnerable System Confidentiality", "code": "VC", "required":true, "options": [{"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "None", "code": "N"}] },
        "VI": { "name": "Vulnerable System Integrity", "code": "VI", "required":true, "options": [{"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "None", "code": "N"}] },
        "VA": { "name": "Vulnerable System Availability", "code": "VA", "required":true, "options": [{"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "None", "code": "N"}] },
        "SC": { "name": "Subsequent System Confidentiality", "code": "SC", "required":true, "options": [{"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "None", "code": "N"}] },
        "SI": { "name": "Subsequent System Integrity", "code": "SI", "required":true, "options": [{"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "None", "code": "N"}] },
        "SA": { "name": "Subsequent System Availability", "code": "SA", "required":true, "options": [{"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "None", "code": "N"}] }
    },
    "Threat Metrics": {
        "E": { "name": "Exploit Maturity", "code": "E", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Attacked", "code": "A"}, {"name": "Proof of concept", "code": "P"}, {"name": "Unreported", "code": "U"}] }
    },
    "Supplemental Metrics": {
        "S": { "name": "Safety", "code": "S", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Negligible", "code": "N"}, {"name": "Present", "code": "P"}] },
        "AU": { "name": "Automatable", "code": "AU", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "No", "code": "N"}, {"name": "Yes", "code": "Y"}] },
        "R": { "name": "Recovery", "code": "R", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Automatic", "code": "A"}, {"name": "User", "code": "U"}, {"name": "Irrecoverable", "code": "I"}] },
        "V": { "name": "Value Density", "code": "V", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Diffuse", "code": "D"}, {"name": "Concentrated", "code": "C"}] },
        "RE": { "name": "Vulnerability Response Effort", "code": "RE", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Low", "code": "L"}, {"name": "Moderate", "code": "M"}, {"name": "High", "code": "H"}] },
        "U": { "name": "Provider Urgency", "code": "U", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Clear", "code": "Clear"}, {"name": "Green", "code": "Green"}, {"name": "Amber", "code": "Amber"}, {"name": "Red", "code": "Red"}] }
    },
    "Environmental (Modified Base Metrics)":{
        "MAV": { "name": "Modified Attack Vector", "code": "MAV", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Network", "code": "N"}, {"name": "Adjacent", "code": "A"}, {"name": "Local", "code": "L"}, {"name": "Physical", "code": "P"}] },
        "MAC": { "name": "Modified Attack Complexity", "code": "MAC", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "MAT": { "name": "Modified Attack Requirements", "code": "MAT", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "None", "code": "N"}, {"name": "Present", "code": "P"}] },
        "MPR": { "name": "Modified Privileges Required", "code": "MPR", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "None", "code": "N"}, {"name": "Low", "code": "L"}, {"name": "High", "code": "H"}] },
        "MUI": { "name": "Modified User Interaction", "code": "MUI", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "None", "code": "N"}, {"name": "Passive", "code": "P"}, {"name": "Active", "code": "A"}] },
        "MVC": { "name": "Modified Vulnerable System Confidentiality", "code": "MVC", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "None", "code": "N"}] },
        "MVI": { "name": "Modified Vulnerable System Integrity", "code": "MVI", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "None", "code": "N"}] },
        "MVA": { "name": "Modified Vulnerable System Availability", "code": "MVA", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "None", "code": "N"}] },
        "MSC": { "name": "Modified Subsequent System Confidentiality", "code": "MSC", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "Negligible", "code": "N"}] },
        "MSI": { "name": "Modified Subsequent System Integrity", "code": "MSI", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Safety", "code": "S"}, {"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "Negligible", "code": "N"}] },
        "MSA": { "name": "Modified Subsequent System Availability", "code": "MSA", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "Safety", "code": "S"}, {"name": "High", "code": "H"}, {"name": "Low", "code": "L"}, {"name": "Negligible", "code": "N"}] }
    },
    "Environmental (Security Requirements)": {
        "CR": { "name": "Confidentiality Requirements", "code": "CR", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "High", "code": "H"}, {"name": "Medium", "code": "M"}, {"name": "Low", "code": "L"}] },
        "IR": { "name": "Integrity Requirements", "code": "IR", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "High", "code": "H"}, {"name": "Medium", "code": "M"}, {"name": "Low", "code": "L"}] },
        "AR": { "name": "Availability Requirements", "code": "AR", "required":false, "options": [{"name": "Not Defined", "code": "X"}, {"name": "High", "code": "H"}, {"name": "Medium", "code": "M"}, {"name": "Low", "code": "L"}] },
    }
};

const cvss_mapping = {
    "4.0": CVSS40_FIELDS,
    "3.1": CVSS31_FIELDS,
    "3.0": CVSS30_FIELDS,
};

const app = {
    currentIndex: 0,
    expandedFolds:  new Set(),
    userStates: {},
    showVectors: true,

    init() {
        this.renderCurationWorkspace();
    },

    renderCurationWorkspace() {
        const item = curationItems[this.currentIndex];
        const total = curationItems.length;
        const progressPercentage = ((this.currentIndex + 1) / total) * 100;

        document.getElementById('progress').value = progressPercentage;
        document.getElementById('progress-text').innerText = `${this.currentIndex + 1} / ${total}`;
        document.getElementById('current-cvss').innerText = `Conflicting CVSS ${item.cvss} Scores`;
        document.getElementById('conflict-reason').innerText = item.conflict_reason? item.conflict_reason: "";

        if (!this.userStates[this.currentIndex]) {
            this.initializeCurationState(item);
        }

        this.renderHeader(item);
        this.renderBody(item);
        this.updateNavButtons();
    },

    initializeCurationState(item) {
        this.userStates[this.currentIndex] = {};
        for (const [catName, metrics] of Object.entries(cvss_mapping[item.cvss])) {
            for (const metricKey of Object.keys(metrics)) {
                const providedValue = item.partial_cvss_curation[metricKey];
                this.userStates[this.currentIndex][metricKey] = (providedValue !== undefined) ? String(providedValue) : "";
            }
        }
    },

    renderHeader(item) {
        const header = document.getElementById('table-header');

        header.innerHTML = `
            <th class="has-text-weight-bold has-text-centered pt-4 is-size-6">CVSS ${item.cvss} Metrics</th>
            <th style="width: 140px;" class="has-text-centered">
            <div>
                <div>
                    <div class="has-text-weight-bold is-size-6">Curation</div>
                </div>
                <button class="button is-small is-outlined is-info mt-auto" onclick="app.resetCurrentCuration()">Reset</button>
            </div>
            </th>
        `;

        item.advisories.forEach((advGroup, groupIdx) => {
            const secondaries = advGroup.secondaries || [];
            const hasSecondaries = secondaries.length > 0;

            const colKey = `${this.currentIndex}-col-${groupIdx}`;
            const isExpanded = this.expandedFolds.has(colKey);

            const primaryTh = document.createElement('th');
            primaryTh.className = "has-text-centered";

            const primaryUrl = baseAdvisoryUrl.replace('0', advGroup.primary.advisory_uid);
            let primaryUidHtml = `
                <div class="mb-3 advisory-wrapper">
                    <a href="${primaryUrl}" target="_blank" rel="noopener noreferrer" class="has-text-link has-text-weight-bold advisory-link">
                        <span>${advGroup.primary.advisory_uid}</span>
                        <span class="icon is-small"><i class="fa fa-external-link"></i></span>
                    </a>
                </div>
                <span class="is-info is-light mb-1 is-size-6">Score: ${advGroup.primary.score || 'NA'}</span><br>
            `;

            let toggleHtml = "";
            if (hasSecondaries) {
                toggleHtml = `
                    <button class="button is-small is-warning is-light mb-2 wrap-button" onclick="app.toggleColumnFold(${groupIdx}); event.stopPropagation();" style="white-space: normal; height: auto;">
                        <span class="icon is-small"><i class="fa ${isExpanded ? 'fa-minus' : 'fa-plus'}"></i></span>
                        <span>${isExpanded ? 'Hide Similar Advisory' : `Show Similar Advisory (+${secondaries.length})`}</span>
                    </button>
                `;
            }

            primaryTh.innerHTML = `
                <div>
                    <div>
                        ${toggleHtml}
                        ${primaryUidHtml}
                    </div>
                    <button
                        class="button is-small is-info mt-auto"
                        onclick="app.pickAdvisory(${groupIdx}, 'primary')"
                        ${advGroup.primary.vector_string ? '' : 'disabled'}>
                        Pick This
                    </button>
                </div>
            `;
            header.appendChild(primaryTh);


            if (hasSecondaries && isExpanded) {
                secondaries.forEach((sec, secIdx) => {
                    const secTh = document.createElement('th');
                    secTh.className = "has-text-centered";
                    secTh.style.backgroundColor = "#fafafa";

                    const secUrl = baseAdvisoryUrl.replace('0', sec.advisory_uid);
                    secTh.innerHTML = `
                        <div>
                            <div class="mb-3 advisory-wrapper">
                                <div>
                                    <span class="tag is-light is-size-7 mb-1">Similar</span>
                                </div>
                                <a href="${secUrl}" target="_blank" rel="noopener noreferrer" class="has-text-grey-dark has-text-weight-bold advisory-link">
                                    <span>${sec.advisory_uid}</span>
                                    <span class="icon is-small" ><i class="fa fa-external-link"></i></span>
                                </a>
                            </div>
                            <span class="is-info is-light mb-1 is-size-6">Score: ${sec.score || 'NA'}</span><br>
                            <button
                                class="button is-small is-info is-light mt-auto"
                                onclick="app.pickAdvisory(${groupIdx}, 'secondary')"
                                ${sec.vector_string ? '' : 'disabled'}>
                                Pick This
                            </button>
                        </div>
                    `;
                    header.appendChild(secTh);
                });
            }
        });
    },

    renderBody(item) {
    const body = document.getElementById('curation-body');
    body.innerHTML = '';

    let totalColumns = 2;
    item.advisories.forEach((advGroup, groupIdx) => {
        totalColumns += 1;
        const colKey = `${this.currentIndex}-col-${groupIdx}`;
        if (this.expandedFolds.has(colKey) && advGroup.secondaries) {
            totalColumns += advGroup.secondaries.length;
        }
    });

    const toggleRow = document.createElement('tr');
    toggleRow.innerHTML = `
        <td colspan="${totalColumns}" class="vector-row-marker" onclick="app.toggleVectors()">
            <span class="icon is-small"><i class="fa ${this.showVectors ? 'fa-chevron-up' : 'fa-chevron-down'}"></i></span>
            ${this.showVectors ? 'Hide' : 'Show'} Advisory Vector String
        </td>
    `;
    body.appendChild(toggleRow);

    if (this.showVectors) {
        const vectorDataRow = document.createElement('tr');
        let rowHtml = `
            <td></td>
            <td class="vector-data-cell is-size-6 has-text-centered py-4">
                ${this.generateCalculatedVectorString(item)}
            </td>
        `;

        item.advisories.forEach((advGroup, groupIdx) => {
            const colKey = `${this.currentIndex}-col-${groupIdx}`;
            const isExpanded = this.expandedFolds.has(colKey);

            rowHtml += `<td class="vector-data-cell is-size-6 has-text-centered py-4 ">${advGroup.primary.vector_string || 'NA'}</td>`;

            if (isExpanded && advGroup.secondaries) {
                advGroup.secondaries.forEach(sec => {
                    rowHtml += `<td class="vector-data-cell is-size-6 has-text-centered py-4" style="background-color: #fafafa;">${sec.vector_string || 'NA'}</td>`;
                });
            }
        });

        vectorDataRow.innerHTML = rowHtml;
        body.appendChild(vectorDataRow);
    }

    for (const [categoryName, metrics] of Object.entries(cvss_mapping[item.cvss])) {

        const catRow = document.createElement('tr');
        catRow.innerHTML = `<td colspan="${totalColumns}" class="metric-category-row">${categoryName}</td>`;
        body.appendChild(catRow);

        for (const [metricKey, metricMeta] of Object.entries(metrics)) {
            const tr = document.createElement('tr');

            tr.innerHTML = `<td class="is-size-6">
                <strong>${metricMeta.name}</strong> 
                <span class="tag is-light is-pulled-right">${metricMeta.code}</span>
            </td>`;

            const curationTd = document.createElement('td');
            curationTd.className = 'curation-select-container';

            const selectDiv = document.createElement('div');
            selectDiv.className = 'select is-fullwidth is-size-6 has-text-centered';

            const select = document.createElement('select');
            select.className = 'is-size-6';
            select.onchange = (e) => this.updateMetricSelection(metricKey, e.target.value);

            const userVal = this.userStates[this.currentIndex][metricKey];

            const unselectedOpt = document.createElement('option');
            unselectedOpt.value = '';
            unselectedOpt.text = 'Select value';
            unselectedOpt.selected = true;
            unselectedOpt.disabled = true;
            if (metricMeta.required && (userVal === undefined || userVal === null || userVal === '')) {
                selectDiv.classList.add('highlight-select');
                selectDiv.classList.add('has-background-warning');
            }
            select.appendChild(unselectedOpt);

            metricMeta.options.forEach(opt => {
                const o = document.createElement('option');
                o.value = opt.code;
                o.text = `${opt.name} (${opt.code})`;
                if (userVal === opt.code) {
                    o.selected = true;
                }
                select.appendChild(o);
            });

            selectDiv.appendChild(select);
            curationTd.appendChild(selectDiv);
            tr.appendChild(curationTd);

            item.advisories.forEach((advGroup, groupIdx) => {
                const colKey = `${this.currentIndex}-col-${groupIdx}`;
                const isExpanded = this.expandedFolds.has(colKey);

                const advTd = document.createElement('td');
                advTd.className = 'immutable-advisory-cell has-text-centered has-text-black is-size-6';
                const advVal = advGroup.primary.vector[metricKey];

                if (advVal === undefined || advVal === null || advVal === '') {
                    advTd.innerText = 'NA';
                    advTd.classList.add('state-undefined');
                } else {
                    const matchedOption = metricMeta.options.find(o => o.code === advVal);
                    advTd.innerText = matchedOption ? `${matchedOption.name} (${advVal})` : advVal;
                }
                tr.appendChild(advTd);

                if (isExpanded && advGroup.secondaries) {
                    advGroup.secondaries.forEach(sec => {
                        const secTd = document.createElement('td');
                        secTd.className = 'immutable-advisory-cell has-text-centered has-text-black is-size-6';
                        secTd.style.backgroundColor = '#fafafa';

                        const secVal = sec.vector[metricKey];

                        if (secVal === undefined || secVal === null || secVal === '') {
                            secTd.innerText = 'NA';
                            secTd.classList.add('state-undefined');
                        } else {
                            const matchedOption = metricMeta.options.find(o => o.code === secVal);
                            secTd.innerText = matchedOption ? `${matchedOption.name} (${secVal})` : secVal;
                        }
                        tr.appendChild(secTd);
                    });
                }
            });

            body.appendChild(tr);
        }
    }
},

    generateCalculatedVectorString(item) {
        const prefix = `CVSS:${item.cvss}`;
        let components = [];

        for (const [cat, metrics] of Object.entries(cvss_mapping[item.cvss])) {
            for (const [metricKey, metricMeta] of Object.entries(metrics)) {
                const userVal = this.userStates[this.currentIndex][metricKey];
                if (userVal && userVal !== "null") {
                    components.push(`${metricMeta.code}:${userVal}`);
                    console.log(userVal)
                }
            }
        }
        return components.length > 0 ? `${prefix}/${components.join('/')}` : "NA";
    },

    updateMetricSelection(metricKey, val) {
        this.userStates[this.currentIndex][metricKey] = val;
        const item = curationItems[this.currentIndex];
        this.renderBody(item); 
    },

    pickAdvisory(groupIdx, type, secIdx = null) {
        const item = curationItems[this.currentIndex];
        let targetAdvisory;

        if (type === 'primary') {
            targetAdvisory = item.advisories[groupIdx].primary.vector;
        } else if (type === 'secondary') {
            targetAdvisory = item.advisories[groupIdx].secondaries[secIdx].vector;
        }

        for (const [cat, metrics] of Object.entries(cvss_mapping[item.cvss])) {
            for (const metricKey of Object.keys(metrics)) {
                if (targetAdvisory[metricKey] !== undefined && targetAdvisory[metricKey] !== '') {
                    this.userStates[this.currentIndex][metricKey] = String(targetAdvisory[metricKey]);
                } else {
                    this.userStates[this.currentIndex][metricKey] = '';
                }
            }
        }
        this.renderBody(item);
    },

    resetCurrentCuration() {
        const item = curationItems[this.currentIndex];
        this.initializeCurationState(item);
        this.renderBody(item);
    },

    toggleVectors() {
        this.showVectors = !this.showVectors;
        const item = curationItems[this.currentIndex];
        this.renderBody(item);
    },

    toggleColumnFold(groupIdx) {
        const colKey = `${this.currentIndex}-col-${groupIdx}`;

        if (this.expandedFolds.has(colKey)) {
            this.expandedFolds.delete(colKey);
        } else {
            this.expandedFolds.add(colKey);
        }

        const item = curationItems[this.currentIndex];
        this.renderHeader(item);
        this.renderBody(item);
    },

    navigate(dir) {
        this.currentIndex += dir;
        this.renderCurationWorkspace();
    },

    updateNavButtons() {
        document.getElementById('prev-btn').disabled = this.currentIndex === 0;
        const isLast = this.currentIndex === curationItems.length - 1;
        document.getElementById('next-btn').classList.toggle('is-hidden', isLast);
        document.getElementById('finish-btn').classList.toggle('is-hidden', !isLast);
    },

};

document.addEventListener('DOMContentLoaded', () => app.init());