// ids/static/ids/js/dashboard.js
document.addEventListener('DOMContentLoaded', () => {
    let latestTimestamp = '';

    // Function to format a date to YYYY-MM-DD HH:MM:SS
    function formatDateToISO(date) {
        const pad = (num) => String(num).padStart(2, '0');
        return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
    }

    function fetchNewFlows() {
        // If latestTimestamp exists, convert it to ISO format
        const timestampParam = latestTimestamp ? formatDateToISO(new Date(latestTimestamp)) : '';
        fetch(`/api/new-flows/?latest_timestamp=${encodeURIComponent(timestampParam)}`)
            .then(response => response.json())
            .then(data => {
                const flowsBody = document.getElementById('flows-body');
                data.flows.forEach(flow => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${flow.timestamp}</td>
                        <td>${flow.protocol}</td>
                        <td>${flow.flow_duration}</td>
                        <td>${flow.total_fwd_packets}</td>
                        <td>${flow.prediction}</td>
                    `;
                    flowsBody.insertBefore(row, flowsBody.firstChild);
                    if (!latestTimestamp || new Date(flow.timestamp) > new Date(latestTimestamp)) {
                        latestTimestamp = flow.timestamp;
                    }
                });
            })
            .catch(error => console.error('Error fetching new flows:', error));
    }

    // Fetch new flows every 5 seconds
    setInterval(fetchNewFlows, 5000);

    // Initial fetch
    fetchNewFlows();
});