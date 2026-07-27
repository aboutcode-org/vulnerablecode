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
        const weaknesses = item.all_cwes;

        const total = curationItems.length;
        const progPercentage = ((this.currentIndex + 1) / total) * 100;
        document.getElementById('progress').value = progPercentage;
        document.getElementById('progress-text').innerText = `${this.currentIndex + 1} / ${total}`;
        document.getElementById('current-purl').innerText = item.conflict_reason;

        if (!this.userStates[this.currentIndex]) {
            this.userStates[this.currentIndex] = {};
            weaknesses.forEach(v => {
                if (item.partial_curation.cwes.includes(v)) this.userStates[this.currentIndex][v] = 'applicable';
                else this.userStates[this.currentIndex][v] = 'empty';
            });
        }

        this.renderHeader(item);
        this.renderBody(item, weaknesses);
        this.updateNavButtons();
    },

    renderHeader(item) {
        const header = document.getElementById('table-header');
        header.innerHTML = `
            <th class="has-text-weight-bold has-text-centered pt-4 is-size-6">Weaknesses</th>
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

    renderBody(item, weaknesses) {
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

        const foldable = this.getFoldableRanges(item, weaknesses);
        for (let i = 0; i < weaknesses.length; i++) {
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
                        ${isExpanded ? 'Hide' : 'Show'} Consensus Range (${range.end - range.start + 1} weaknesses)
                    </td>`;
                    body.appendChild(marker);
                }
                if (!isExpanded) {
                    if (i === range.end) continue;
                    i = range.end;
                    continue;
                }
            }
            body.appendChild(this.createRow(weaknesses[i], item));
        }
    },

    resetCurrentCuration() {
        const item = curationItems[this.currentIndex];
        const weaknesses = item.all_cwes;
        weaknesses.forEach(v => {
            if (item.partial_curation.cwes.includes(v)) {
                this.userStates[this.currentIndex][v] = 'applicable';
            }
            else {
                this.userStates[this.currentIndex][v] = 'empty';
            }
        });
        this.renderBody(item, weaknesses);
    },

    createRow(v, item) {
        const tr = document.createElement('tr');
        const cwe_info = item.cwe_details[v]
        const state = this.userStates[this.currentIndex][v];
        tr.innerHTML = `
            <td
                class="has-text-weight-bold"
                style="word-break: break-all;"
            >
                CWE-${v}<br>
                <span class="has-text-weight-normal">${cwe_info.name}</span>
                <span
                    class="icon has-tooltip-multiline has-tooltip-top has-tooltip-arrow has-text-weight-normal"
                    data-tooltip="${cwe_info.description}"
                >
                    <i class="fa fa-info-circle"></i>
                </span>
            </td>`;
        const userTd = document.createElement('td');
        userTd.className = `curation-cell state-${state}`;
        userTd.innerText = state === "empty"? "Select value": state.replace('-', ' ').toUpperCase();
        userTd.onclick = () => this.cycleState(v);
        tr.appendChild(userTd);
        
        item.advisories.forEach((advGroup, groupIdx) => {
            const colKey = `${this.currentIndex}-col-${groupIdx}`;
            const isExpanded = this.expandedFolds.has(colKey);

            const primaryState = advGroup.cwes.includes(v) ? 'applicable' : 'not-applicable';
            const td = document.createElement('td');
            td.className = `state-${primaryState} has-text-centered advisory-cell`;
            td.innerText = primaryState.replace('-', ' ').toUpperCase();
            tr.appendChild(td);

            if (isExpanded && advGroup.secondaries) {
                advGroup.secondaries.forEach(sec => {
                    const secAffected = advGroup.cwes;
                    
                    const secState = secAffected.includes(v) ? 'applicable' : 'not-applicable'; 
                    const secTd = document.createElement('td');
                    secTd.className = `state-${secState} has-text-centered advisory-cell`;
                    secTd.style.borderLeft = "1px dashed #dbdbdb";
                    secTd.innerText = secState.replace('-', ' ').toUpperCase();
                    tr.appendChild(secTd);
                });
            }
        });
        return tr;
    },

    getFoldableRanges(item, weaknesses) {
        const ranges = [];
        const foldThreshHold = 3;
        let start = -1;
        for (let i = 0; i < weaknesses.length; i++) {
            const v = weaknesses[i];
            const states = item.advisories.map(a => a.cwes.includes(v) ? 'applicable' : 'not-applicable');
            const allMatch = states.every(s => s === states[0]);
            if (allMatch) {
                if (start === -1) start = i;
            } else {
                if (start !== -1 && (i - start) >= foldThreshHold) ranges.push({
                    start,
                    end: i - 1
                });
                start = -1;
            }
        }
        if (start !== -1 && (weaknesses.length - start) >= foldThreshHold) ranges.push({
            start,
            end: weaknesses.length - 1
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
        const weaknesses = item.all_cwes;
        this.renderBody(item, weaknesses);
    },

    toggleColumnFold(groupIdx) {
        const colKey = `${this.currentIndex}-col-${groupIdx}`;
        if (this.expandedFolds.has(colKey)) {
            this.expandedFolds.delete(colKey);
        } else {
            this.expandedFolds.add(colKey);
        }
        const item = curationItems[this.currentIndex];
        const weaknesses = item.all_cwes;
        
        this.renderHeader(item);
        this.renderBody(item, weaknesses);
    },

    toggleRanges() {
        this.showRanges = !this.showRanges;
        const item = curationItems[this.currentIndex];
        const weaknesses = item.all_cwes;
        this.renderBody(item, weaknesses);
    },

    cycleState(v) {
        const seq = ['applicable', 'not-applicable'];
        const current = this.userStates[this.currentIndex][v];
        this.userStates[this.currentIndex][v] = seq[(seq.indexOf(current) + 1) % seq.length];
        const item = curationItems[this.currentIndex];
        const weaknesses = item.all_cwes;
        this.renderBody(item, weaknesses);
    },

    pickAdvisory(advIdx, type, secondaryIdx) {
        const item = curationItems[this.currentIndex];
        const advGroup = item.advisories[advIdx];
        const weaknesses = item.all_cwes;
        
        weaknesses.forEach(v => {
            if (advGroup.cwes.includes(v)) this.userStates[this.currentIndex][v] = 'applicable';
            else this.userStates[this.currentIndex][v] = 'not-applicable';
        });
        this.renderBody(item, weaknesses);
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