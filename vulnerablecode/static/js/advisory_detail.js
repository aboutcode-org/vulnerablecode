(function () {
    let epssChartInstance = null;
    
    const [btnChart, btnTable, chartWrap, tableWrap] = 
        ["btn-load-epss-chart", "btn-load-epss-table", "epss-chart-wrap", "epss-history-table-wrap"]
        .map(id => document.getElementById(id));

    const getHistoryData = () => JSON.parse(document.getElementById('epss-history-data')?.textContent || "[]");
    const toggleDisplay = (el) => el.style.display = el.style.display === "none" ? "block" : "none";

    const updateBtn = (btn, wrap) => {
        if (!btn || !wrap) return;
        const isHidden = wrap.style.display === "none";
        btn.textContent = btn.textContent.replace(isHidden ? "Hide" : "See", isHidden ? "See" : "Hide");
    };

    function renderChart() {
        const data = getHistoryData();
        if (!data.length) return;

        toggleDisplay(chartWrap);
        updateBtn(btnChart, chartWrap);
        
        if (chartWrap.style.display === "none" || epssChartInstance) return;

        const history = [];
        const map = new Map(data.map(h => [new Date(h.published_at + "T00:00:00").setHours(0,0,0,0), h]));
        
        const end = new Date(data[data.length - 1].published_at + "T00:00:00").setHours(0,0,0,0);
        let start = new Date(end);
        start.setDate(start.getDate() - 30);
        
        const actualStart = new Date(data[0].published_at + "T00:00:00").setHours(0,0,0,0);
        start = new Date(Math.max(start.getTime(), actualStart));

        for (let d = start; d.getTime() <= end; d.setDate(d.getDate() + 1)) {
            history.push(map.get(d.getTime()) || {
                published_at: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`,
                score: null, percentile: null
            });
        }
        try {
            epssChartInstance = bb.generate({
                bindto: "#epss-chart",
                size: { height: 260 }, padding: { right: 25 },
                data: {
                    x: "Date", xFormat: "%Y-%m-%d",
                    columns: [
                        ["Date", ...history.map(h => h.published_at || "")],
                        ["Score", ...history.map(h => h.score === null ? null : parseFloat(h.score))],
                        ["Percentile", ...history.map(h => h.percentile === null ? null : parseFloat(h.percentile))],
                    ],
                    type: "line", colors: { Score: "#df25e6ff", Percentile: "#00d1b2" },
                },
                //Handles missing dates
                line: { connectNull: false },
                axis: {
                    x: { type: "timeseries", tick: { format: "%b %d", count: Math.min(history.length, 6), fit: true } },
                    y: { min: 0, max: 1, padding: { top: 10, bottom: 0 }, tick: { format: v => v.toFixed(4) } },
                },
                point: { r: 3 }, legend: { show: true },
                tooltip: {
                    format: {
                        title: d => d instanceof Date ? `${d.toLocaleString('en-us', {month: 'short'})} ${String(d.getDate()).padStart(2, '0')}, ${d.getFullYear()}` : String(d),
                        value: v => v.toFixed(5),
                    },
                },
            });
        } catch (e) { console.error("[epss-chart]", e); }
    }

    btnChart?.addEventListener("click", renderChart);
    btnTable?.addEventListener("click", () => {
        toggleDisplay(tableWrap);
        updateBtn(btnTable, tableWrap);
    });

    updateBtn(btnChart, chartWrap);
    updateBtn(btnTable, tableWrap);
})();
