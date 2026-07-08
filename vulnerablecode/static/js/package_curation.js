const app = {
    currentIndex: 0,
    userStates: {},
    expandedFolds: new Set(),
    showRanges: false,
    foldAgreementBlocks: true,
    init() {
        this.renderPackageCuration();

        document.querySelector('.summary-text')?.addEventListener('click', (e) => {
            if (e.target.closest('a')) {
                e.target.target = '_blank';
            }
        });
    },

    renderPackageCuration() {
        const item = curationItems[this.currentIndex];
        const versions = item.all_versions || item.all_version;

        const total = curationItems.length;
        const progPercentage = ((this.currentIndex + 1) / total) * 100;
        document.getElementById('progress').value = progPercentage;
        document.getElementById('progress-text').innerText = `${this.currentIndex + 1} / ${total}`;
        document.getElementById('current-purl').innerText = item.purl;

        if (!this.userStates[this.currentIndex]) {
            this.userStates[this.currentIndex] = {};
            versions.forEach(v => {
                if (item.partial_curation.affected.includes(v)) this.userStates[this.currentIndex][v] = 'affected';
                else if (item.partial_curation.fixing.includes(v)) this.userStates[this.currentIndex][v] = 'fixed';
                else this.userStates[this.currentIndex][v] = 'empty';
            });
        }
        this.renderConflictSummary(item);
        this.renderHeader(item);
        this.renderBody(item, versions);
        this.updateNavButtons();
    },

    renderConflictSummary(item){
        const el = document.getElementById("conflict-reason");
        const btn = document.getElementById("toggle-conflict");

        el.innerText = item.conflict_reason;
        el.classList.add("truncate-conflict-summary");
        const hasOverflow = el.scrollHeight > el.clientHeight;

        if (hasOverflow) {
            btn.style.display = "inline";

            btn.onclick = () => {
                const isTruncated = el.classList.toggle("truncate-conflict-summary");
                btn.innerText = isTruncated ? "Show more" : "Show less";
            };
        } else {
            btn.style.display = "none";
            el.classList.remove("truncate-conflict-summary");
        }
    },

    renderHeader(item) {
        const header = document.getElementById('table-header');
        header.innerHTML = `
            <th class="has-text-weight-bold has-text-centered pt-4 is-size-6">Package Versions</th>
            <th style="width: 140px;" class="has-text-centered">
                <div>
                    <div>
                        <div class="has-text-weight-bold">Curation</div>
                    </div>
                    <button class="button is-small is-outlined is-info mt-auto" onclick="app.resetCurrentCuration()">Reset</button>
                </div>
            </th>`;
            
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
                    <button class="button is-small is-info mt-auto" onclick="app.pickAdvisory(${groupIdx}, 'primary')">Pick This</button>
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
                            <button class="button is-small is-info is-light mt-auto" onclick="app.pickAdvisory(${groupIdx}, 'secondary', ${secIdx})">Pick This</button>
                        </div>
                    `;
                    header.appendChild(secTh);
                });
            }
        });
    },

    renderBody(item, versions) {
        const body = document.getElementById('curation-body');
        body.innerHTML = '';
        
        let totalColumns = 2; 
        item.advisories.forEach((advGroup, groupIdx) => {
            totalColumns += 1;
            const colKey = `${this.currentIndex}-col-${groupIdx}`;
            if (this.expandedFolds.has(colKey)) {
                totalColumns += (advGroup.secondaries || []).length;
            }
        });

        const rangeToggleRow = document.createElement('tr');
        rangeToggleRow.innerHTML = `
            <td colspan="${totalColumns}" class="range-row-marker" onclick="app.toggleRanges()">
                <span class="icon is-small"><i class="fa ${this.showRanges ? 'fa-chevron-up' : 'fa-chevron-down'}"></i></span>
                ${this.showRanges ? 'Hide' : 'Show'} Version Ranges
            </td>`;
        body.appendChild(rangeToggleRow);
        
        if (this.showRanges) {
            const rangeDataRow = document.createElement('tr');
            let rowHtml = `<td></td><td></td>`;
            
            item.advisories.forEach((advGroup, groupIdx) => {
                const colKey = `${this.currentIndex}-col-${groupIdx}`;
                const isExpanded = this.expandedFolds.has(colKey);
                
                const renderRangeHtml = (ranges) => ranges.map(r => {
                    let htmlLines = [];
                    if (r.affected_vers && r.affected_vers.trim() !== "") {
                        htmlLines.push(`<div><span class="has-text-weight-semibold">Affected:</span> ${r.affected_vers}</div>`);
                    }
                    if (r.fixing_vers && r.fixing_vers.trim() !== "") {
                        htmlLines.push(`<div><span class="has-text-weight-semibold">Fixing:</span> ${r.fixing_vers}</div>`);
                    }
                    return htmlLines.length > 0 ? htmlLines.join('') : '<div>No range specified</div>';
                }).join('<hr class="my-1" style="background-color: #dbdbdb; height: 1px;">');

                rowHtml += `<td class="range-data-cell">${renderRangeHtml(advGroup.primary.vers_ranges)}</td>`;

                if (isExpanded && advGroup.secondaries) {
                    advGroup.secondaries.forEach(sec => {
                        rowHtml += `<td class="range-data-cell" style="background-color: #f5f5f5;">${renderRangeHtml(sec.vers_ranges)}</td>`;
                    });
                }
            });
            
            rangeDataRow.innerHTML = rowHtml;
            body.appendChild(rangeDataRow);
        }
        
        const foldable = this.getFoldableRanges(item, versions);
        for (let i = 0; i < versions.length; i++) {
            const range = foldable.find(r => i >= r.start && i <= r.end);
            if (range) {
                const foldKey = `${this.currentIndex}-${range.start}`;
                let isExpanded = this.expandedFolds.has(foldKey);
                if (!this.foldAgreementBlocks) {
                    isExpanded = !this.expandedFolds.has(`${this.currentIndex}-${range.start}-collapsed`);
                }
                if (i === range.start) {
                    const marker = document.createElement('tr');
                    marker.innerHTML = `<td colspan="${totalColumns}" class="folded-row-marker ${isExpanded ? 'is-expanded' : ''}" onclick="app.toggleFold(${range.start})">
                        <span class="icon is-small"><i class="fa fa-chevron-down"></i></span>
                        ${isExpanded ? 'Hide' : 'Show'} Consensus Range (${range.end - range.start + 1} versions)
                    </td>`;
                    body.appendChild(marker);
                }
                if (!isExpanded) {
                    if (i === range.end) continue;
                    i = range.end;
                    continue;
                }
            }
            body.appendChild(this.createRow(versions[i], item));
        }
    },

    resetCurrentCuration() {
        const item = curationItems[this.currentIndex];
        const versions = item.all_versions || item.all_version;
        versions.forEach(v => {
            if (item.partial_curation.affected.includes(v)) {
                this.userStates[this.currentIndex][v] = 'affected';
            } else if (item.partial_curation.fixing.includes(v)) {
                this.userStates[this.currentIndex][v] = 'fixed';
            } else {
                this.userStates[this.currentIndex][v] = 'empty';
            }
        });
        this.renderBody(item, versions);
    },

    createRow(v, item) {
        const tr = document.createElement('tr');
        const state = this.userStates[this.currentIndex][v];
        tr.innerHTML = `<td class="has-text-weight-bold" style="word-break: break-all;">${v}</td>`;
        const userTd = document.createElement('td');
        userTd.className = `curation-cell state-${state}`;
        userTd.innerText = state === "empty"? "Select value": state.toUpperCase();
        userTd.onclick = () => this.cycleState(v);
        tr.appendChild(userTd);
        
        item.advisories.forEach((advGroup, groupIdx) => {
            const colKey = `${this.currentIndex}-col-${groupIdx}`;
            const isExpanded = this.expandedFolds.has(colKey);

            const primaryState = advGroup.affected.includes(v) ? 'affected' : (advGroup.fixing.includes(v) ? 'fixed' : 'unaffected');
            const td = document.createElement('td');
            td.className = `state-${primaryState} has-text-centered advisory-cell`;
            td.innerText = primaryState.toUpperCase();
            tr.appendChild(td);

            if (isExpanded && advGroup.secondaries) {
                advGroup.secondaries.forEach(sec => {
                    const secAffected = sec.affected || advGroup.affected;
                    const secFixing = sec.fixing || advGroup.fixing;
                    
                    const secState = secAffected.includes(v) ? 'affected' : (secFixing.includes(v) ? 'fixed' : 'unaffected'); 
                    const secTd = document.createElement('td');
                    secTd.className = `state-${secState} has-text-centered advisory-cell`;
                    secTd.style.borderLeft = "1px dashed #dbdbdb";
                    secTd.innerText = secState.toUpperCase();
                    tr.appendChild(secTd);
                });
            }
        });
        return tr;
    },

    getFoldableRanges(item, versions) {
        const ranges = [];
        let start = -1;
        for (let i = 0; i < versions.length; i++) {
            const v = versions[i];
            const states = item.advisories.map(a => a.affected.includes(v) ? 'affected' : (a.fixing.includes(v) ? 'fixed' : 'unaffected'));
            const allMatch = states.every(s => s === states[0]);
            if (allMatch) {
                if (start === -1) start = i;
            } else {
                if (start !== -1 && (i - start) >= 3) ranges.push({
                    start,
                    end: i - 1
                });
                start = -1;
            }
        }
        if (start !== -1 && (versions.length - start) >= 3) ranges.push({
            start,
            end: versions.length - 1
        });
        return ranges;
    },

    toggleFold(startIdx) {
        const foldKey = `${this.currentIndex}-${startIdx}`;
        const collapseKey = `${this.currentIndex}-${startIdx}-collapsed`;

        if (this.foldAgreementBlocks) {
            if (this.expandedFolds.has(foldKey)) {
                this.expandedFolds.delete(foldKey);
            } else {
                this.expandedFolds.add(foldKey);
            }
        } else {
            if (this.expandedFolds.has(collapseKey)) {
                this.expandedFolds.delete(collapseKey);
            } else {
                this.expandedFolds.add(collapseKey);
            }
        }
        const item = curationItems[this.currentIndex];
        const versions = item.all_versions || item.all_version;
        this.renderBody(item, versions);
    },

    toggleColumnFold(groupIdx) {
        const colKey = `${this.currentIndex}-col-${groupIdx}`;
        if (this.expandedFolds.has(colKey)) {
            this.expandedFolds.delete(colKey);
        } else {
            this.expandedFolds.add(colKey);
        }
        const item = curationItems[this.currentIndex];
        const versions = item.all_versions || item.all_version;
        
        this.renderHeader(item);
        this.renderBody(item, versions);
    },

    toggleRanges() {
        this.showRanges = !this.showRanges;
        const item = curationItems[this.currentIndex];
        const versions = item.all_versions || item.all_version;
        this.renderBody(item, versions);
    },

    cycleState(v) {
        const seq = ['unaffected', 'affected', 'fixed'];
        const current = this.userStates[this.currentIndex][v];
        this.userStates[this.currentIndex][v] = seq[(seq.indexOf(current) + 1) % 3];
        const item = curationItems[this.currentIndex];
        const versions = item.all_versions || item.all_version;
        this.renderBody(item, versions);
    },

    pickAdvisory(advIdx, type, secondaryIdx) {
        const item = curationItems[this.currentIndex];
        const advGroup = item.advisories[advIdx];
        const versions = item.all_versions || item.all_version;
        
        versions.forEach(v => {
            if (advGroup.affected.includes(v)) this.userStates[this.currentIndex][v] = 'affected';
            else if (advGroup.fixing.includes(v)) this.userStates[this.currentIndex][v] = 'fixed';
            else this.userStates[this.currentIndex][v] = 'unaffected';
        });
        this.renderBody(item, versions);
    },

    navigate(dir) {
        this.currentIndex += dir;
        this.renderPackageCuration();
    },

    updateNavButtons() {
        document.getElementById('prev-btn').disabled = this.currentIndex === 0;
        const isLast = this.currentIndex === curationItems.length - 1;
        document.getElementById('next-btn').classList.toggle('is-hidden', isLast);
        document.getElementById('finish-btn').classList.toggle('is-hidden', !isLast);
    },

};
document.addEventListener('DOMContentLoaded', () => app.init());