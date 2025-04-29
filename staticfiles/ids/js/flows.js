document.addEventListener('DOMContentLoaded', () => {
    let currentPage = 1;
    const pageSize = 10;
    let totalFlows = 0;

    const flowsTable = document.getElementById('flowsTable');
    const loading = document.getElementById('loading');
    const paginationInfo = document.getElementById('paginationInfo');
    const prevPage = document.getElementById('prevPage');
    const nextPage = document.getElementById('nextPage');
    const flowCount = document.getElementById('flowCount');

    const applyFiltersBtn = document.getElementById('applyFilters');
    const resetFiltersBtn = document.getElementById('resetFilters');

    function loadFlows() {
        loading.style.display = 'block';
        const filters = getFilters();
        const url = `/api/flows/?page=${currentPage}&limit=${pageSize}&${filters}`;

        fetch(url)
            .then(response => response.json())
            .then(data => {
                flowsTable.innerHTML = '';
                totalFlows = data.count;
                flowCount.textContent = totalFlows;

                data.results.forEach(flow => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${flow.id.slice(0, 8)}</td>
                        <td>${new Date(flow.timestamp).toLocaleString()}</td>
                        <td>${flow.source_ip}:${flow.source_port}</td>
                        <td>${flow.destination_ip}:${flow.destination_port}</td>
                        <td>${flow.protocol}</td>
                        <td>${flow.packet_count}</td>
                        <td>${flow.byte_count}</td>
                        <td>${flow.duration.toFixed(2)}s</td>
                        <td>${flow.flow_rate ? flow.flow_rate.toFixed(2) : 'N/A'} pkt/s</td>
                        <td>${flow.alert_count}</td>
                        <td><button class="btn btn-sm btn-info view-details" data-id="${flow.id}">Details</button></td>
                    `;
                    flowsTable.appendChild(row);
                });

                updatePagination();
                loading.style.display = 'none';

                document.querySelectorAll('.view-details').forEach(btn => {
                    btn.addEventListener('click', () => showFlowDetails(btn.dataset.id));
                });
            })
            .catch(error => {
                console.error('Error loading flows:', error);
                loading.style.display = 'none';
            });
    }

    function getFilters() {
        const sourceIp = document.getElementById('sourceIpFilter').value;
        const destIp = document.getElementById('destIpFilter').value;
        const protocol = document.getElementById('protocolFilter').value;
        const hasAlerts = document.getElementById('hasAlertsFilter').value;
        const timeRange = document.getElementById('timeRangeFilter').value;

        let filters = '';
        if (sourceIp) filters += `source_ip=${sourceIp}&`;
        if (destIp) filters += `destination_ip=${destIp}&`;
        if (protocol) filters += `protocol=${protocol}&`;
        if (hasAlerts === 'yes') filters += 'alert_count__gt=0&';
        if (hasAlerts === 'no') filters += 'alert_count=0&';
        if (timeRange !== '0') {
            const startTime = new Date(Date.now() - timeRange * 3600000).toISOString();
            filters += `start_time=${startTime}&`;
        }
        return filters;
    }

    function updatePagination() {
        const start = (currentPage - 1) * pageSize + 1;
        const end = Math.min(currentPage * pageSize, totalFlows);
        paginationInfo.textContent = `Showing ${start}-${end} of ${totalFlows}`;
        prevPage.disabled = currentPage === 1;
        nextPage.disabled = end >= totalFlows;
    }

    function showFlowDetails(flowId) {
        fetch(`/api/flows/${flowId}/`)
            .then(response => response.json())
            .then(flow => {
                document.getElementById('flow-id').textContent = flow.id;
                document.getElementById('flow-time').textContent = new Date(flow.timestamp).toLocaleString();
                document.getElementById('flow-source-detail').textContent = `${flow.source_ip}:${flow.source_port}`;
                document.getElementById('flow-destination-detail').textContent = `${flow.destination_ip}:${flow.destination_port}`;
                document.getElementById('flow-protocol-detail').textContent = flow.protocol;
                document.getElementById('flow-packets-detail').textContent = flow.packet_count;
                document.getElementById('flow-bytes-detail').textContent = flow.byte_count;
                document.getElementById('flow-duration-detail').textContent = `${flow.duration.toFixed(2)}s`;
                document.getElementById('flow-rate-detail').textContent = flow.flow_rate ? `${flow.flow_rate.toFixed(2)} pkt/s` : 'N/A';
                document.getElementById('flow-byte-rate-detail').textContent = flow.byte_rate ? `${flow.byte_rate.toFixed(2)} B/s` : 'N/A';
                document.getElementById('flow-packet-data').textContent = flow.packet_data ? JSON.stringify(JSON.parse(flow.packet_data), null, 2) : 'No packet data available';

                const modal = new bootstrap.Modal(document.getElementById('flowDetailModal'));
                modal.show();
            });
    }

    prevPage.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            loadFlows();
        }
    });

    nextPage.addEventListener('click', () => {
        if (currentPage * pageSize < totalFlows) {
            currentPage++;
            loadFlows();
        }
    });

    applyFiltersBtn.addEventListener('click', () => {
        currentPage = 1;
        loadFlows();
    });

    resetFiltersBtn.addEventListener('click', () => {
        document.getElementById('flowFilters').reset();
        currentPage = 1;
        loadFlows();
    });

    loadFlows();
    setInterval(loadFlows, 30000); // Refresh every 30 seconds
});