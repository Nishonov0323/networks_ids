// static/ids/js/alerts.js
document.addEventListener('DOMContentLoaded', () => {
    let currentPage = 1;
    const pageSize = 10;
    let totalAlerts = 0;

    const alertsTable = document.getElementById('alertsTable');
    const loading = document.getElementById('loading');
    const paginationInfo = document.getElementById('paginationInfo');
    const prevPage = document.getElementById('prevPage');
    const nextPage = document.getElementById('nextPage');
    const alertCount = document.getElementById('alertCount');
    const applyFiltersBtn = document.getElementById('applyFilters');
    const resetFiltersBtn = document.getElementById('resetFilters');
    const confidenceValue = document.getElementById('confidenceValue');
    const confidenceFilter = document.getElementById('confidenceFilter');

    // Confidence slider qiymatini yangilash
    confidenceFilter.addEventListener('input', () => {
        confidenceValue.textContent = `${(confidenceFilter.value * 100).toFixed(0)}%`;
    });

    function loadAlerts() {
        loading.style.display = 'block';
        const filters = getFilters();
        const url = `/api/alerts/?page=${currentPage}&limit=${pageSize}&${filters}`;

        fetch(url)
            .then(response => response.json())
            .then(data => {
                alertsTable.innerHTML = '';
                totalAlerts = data.count;
                alertCount.textContent = totalAlerts;

                data.results.forEach(alert => {
                    const row = document.createElement('tr');
                    row.classList.add(getStatusClass(alert.status));
                    row.innerHTML = `
                        <td>${alert.id.slice(0, 8)}</td>
                        <td>${new Date(alert.timestamp).toLocaleString()}</td>
                        <td>${alert.flow.source_ip}:${alert.flow.source_port}</td>
                        <td>${alert.flow.destination_ip}:${alert.flow.destination_port}</td>
                        <td>${alert.attack_category || 'N/A'}</td>
                        <td>${alert.attack_subcategory || 'N/A'}</td>
                        <td>${alert.rule ? alert.rule.name : 'ML Detection'}</td>
                        <td>${(alert.confidence * 100).toFixed(1)}%</td>
                        <td>${alert.status}</td>
                        <td><button class="btn btn-sm btn-info view-details" data-id="${alert.id}">Details</button></td>
                    `;
                    alertsTable.appendChild(row);
                });

                updatePagination();
                loading.style.display = 'none';

                document.querySelectorAll('.view-details').forEach(btn => {
                    btn.addEventListener('click', () => showAlertDetails(btn.dataset.id));
                });
            })
            .catch(error => {
                console.error('Error loading alerts:', error);
                loading.style.display = 'none';
            });
    }

    function getStatusClass(status) {
        switch (status) {
            case 'NEW': return 'table-danger';
            case 'INVESTIGATING': return 'table-warning';
            case 'RESOLVED': return 'table-success';
            case 'FALSE_POSITIVE': return 'table-secondary';
            default: return '';
        }
    }

    function getFilters() {
        const status = document.getElementById('statusFilter').value;
        const category = document.getElementById('categoryFilter').value;
        const confidence = document.getElementById('confidenceFilter').value;
        const timeRange = document.getElementById('timeRangeFilter').value;

        let filters = '';
        if (status) filters += `status=${status}&`;
        if (category) filters += `attack_category=${category}&`;
        if (confidence > 0) filters += `confidence__gte=${confidence}&`;
        if (timeRange !== '0') {
            const startTime = new Date(Date.now() - timeRange * 3600000).toISOString();
            filters += `timestamp__gte=${startTime}&`;
        }
        return filters;
    }

    function updatePagination() {
        const start = (currentPage - 1) * pageSize + 1;
        const end = Math.min(currentPage * pageSize, totalAlerts);
        paginationInfo.textContent = `Showing ${start}-${end} of ${totalAlerts}`;
        prevPage.disabled = currentPage === 1;
        nextPage.disabled = end >= totalAlerts;
    }

    function showAlertDetails(alertId) {
        fetch(`/api/alerts/${alertId}/`)
            .then(response => response.json())
            .then(alert => {
                document.getElementById('alert-id').textContent = alert.id;
                document.getElementById('alert-time').textContent = new Date(alert.timestamp).toLocaleString();
                document.getElementById('alert-category').textContent = alert.attack_category || 'N/A';
                document.getElementById('alert-subcategory').textContent = alert.attack_subcategory || 'N/A';
                document.getElementById('alert-rule').textContent = alert.rule ? alert.rule.name : 'ML Detection';
                document.getElementById('alert-confidence').textContent = `${(alert.confidence * 100).toFixed(1)}%`;
                document.getElementById('alert-status').value = alert.status;
                document.getElementById('flow-source').textContent = `${alert.flow.source_ip}:${alert.flow.source_port}`;
                document.getElementById('flow-destination').textContent = `${alert.flow.destination_ip}:${alert.flow.destination_port}`;
                document.getElementById('flow-protocol').textContent = alert.flow.protocol;
                document.getElementById('flow-packets').textContent = alert.flow.packet_count;
                document.getElementById('flow-bytes').textContent = alert.flow.byte_count;
                document.getElementById('flow-duration').textContent = `${alert.flow.duration.toFixed(2)}s`;
                document.getElementById('flow-rate').textContent = alert.flow.flow_rate ? `${alert.flow.flow_rate.toFixed(2)} pkt/s` : 'N/A';
                document.getElementById('alert-details').textContent = alert.details || 'No additional details available';

                const modal = new bootstrap.Modal(document.getElementById('alertDetailModal'));
                modal.show();

                document.getElementById('saveAlertStatus').onclick = () => saveAlertStatus(alertId);
            });
    }

    function saveAlertStatus(alertId) {
        const newStatus = document.getElementById('alert-status').value;
        fetch(`/api/alerts/${alertId}/`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken'),
            },
            body: JSON.stringify({ status: newStatus }),
        })
            .then(response => response.json())
            .then(() => {
                bootstrap.Modal.getInstance(document.getElementById('alertDetailModal')).hide();
                loadAlerts();
            })
            .catch(error => console.error('Error updating status:', error));
    }

    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    prevPage.addEventListener('click', () => {
        if (currentPage > 1) {
            currentPage--;
            loadAlerts();
        }
    });

    nextPage.addEventListener('click', () => {
        if (currentPage * pageSize < totalAlerts) {
            currentPage++;
            loadAlerts();
        }
    });

    applyFiltersBtn.addEventListener('click', () => {
        currentPage = 1;
        loadAlerts();
    });

    resetFiltersBtn.addEventListener('click', () => {
        document.getElementById('alertFilters').reset();
        confidenceValue.textContent = '0%';
        currentPage = 1;
        loadAlerts();
    });

    loadAlerts();
    setInterval(loadAlerts, 30000); // Refresh every 30 seconds
});