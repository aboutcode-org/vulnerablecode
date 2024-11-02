// static/js/pagination.js
// This function would handles the pagination dropdown change event, maintaining existing search parameters.
// This would also update the page size in the URL and reloads the page with the new page size parameter. 
function handlePageSizeChange(value) {
    const url = new URL(window.location.href);
    const params = new URLSearchParams(url.search);
    params.set('page_size', value);
    params.delete('page');
    const search = params.get('search');
    if (search) {
        params.set('search', search);
    }
    const newUrl = `${window.location.pathname}?${params.toString()}`;
    if (window.location.href !== newUrl) {
        window.location.href = newUrl;
    }
}