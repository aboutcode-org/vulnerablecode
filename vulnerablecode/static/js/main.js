//
// Selected parts from https://bulma.io/lib/main.js?v=202104191409
//

'use strict';

function goToTab(tabName) {
    const tabsContainer = document.querySelector('div.tabs.is-boxed');
    if (!tabsContainer) return;

    const targetLink = tabsContainer.querySelector(`[data-tab='${tabName}']`);
    const targetTabContent = document.querySelector(`[data-content='${tabName}']`);
    if (!targetLink || !targetTabContent) return;

    const activeLink = tabsContainer.querySelector('li.is-active');
    const activeTabContent = document.querySelector('div.tab-div.is-active');

    if (activeLink) activeLink.classList.remove('is-active');
    if (activeTabContent) activeTabContent.classList.remove('is-active');

    targetLink.classList.add('is-active');
    targetTabContent.classList.add('is-active');
}

function setupTabs() {
    const tabsContainer = document.querySelector('div.tabs.is-boxed');
    if (!tabsContainer || tabsContainer.dataset.tabsReady === '1') return;
    tabsContainer.dataset.tabsReady = '1';

    // Delegate from the tab list so clicks on <li>, <a>, or nested <span> all work.
    tabsContainer.addEventListener('click', function (event) {
        const tabItem = event.target.closest('li[data-tab]');
        if (!tabItem || !tabsContainer.contains(tabItem)) return;

        event.preventDefault();
        goToTab(tabItem.getAttribute('data-tab'));
    });
}

// Utils, available globally

function getAll(selector) {
    var parent = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : document;
    return Array.prototype.slice.call(parent.querySelectorAll(selector), 0);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', setupTabs);
} else {
    setupTabs();
}
