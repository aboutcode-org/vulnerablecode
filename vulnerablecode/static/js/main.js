//
// Selected parts from https://bulma.io/lib/main.js?v=202104191409
//

'use strict';

function setupTabs() {
    //    const $tabLinks = getAll('.tabs a');
    const $tabLinks = getAll('.tabs li');

    $tabLinks.forEach(function ($el) {
        $el.addEventListener('click', function (event) {
            const activeLink = document.querySelector('.tabs .is-active');
            //            const activeTabContent = document.querySelector('.tab-content.is-active');
            const activeTabContent = document.querySelector('.tab-div.is-active');
            const target_id = $el.dataset.target;
            const targetTabContent = document.getElementById(target_id);

            activeLink.classList.remove('is-active');
            $el.parentNode.classList.add('is-active');
            if (activeTabContent) activeTabContent.classList.remove('is-active');
            if (targetTabContent) targetTabContent.classList.add('is-active');
        });
    });
}

// Utils, available globally

function getAll(selector) {
    var parent = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : document;
    return Array.prototype.slice.call(parent.querySelectorAll(selector), 0);
}

document.addEventListener('DOMContentLoaded', function () {
    setupTabs();
});