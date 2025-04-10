// static/ids/js/dashboard.js
document.addEventListener('DOMContentLoaded', () => {
    const alertsTable = document.getElementById('alertsTable');

    // Load recent alerts
    function loadRecentAlerts() {
        fetch('/api/alerts/?limit=10')
            .then(response => response.json())
            .then(data => {
                alertsTable.innerHTML = '';
                data.results.forEach(alert => {
                    const row = document.createElement('tr');
                    row.classList.add(getStatusClass(alert.status));
                    row.innerHTML = `
                        <td>${new Date(alert.timestamp).toLocaleString()}</td>
                        <td>${alert.flow.source_ip}</td>
                        <td>${alert.flow.destination_ip}</td>
                        <td>${alert.attack_category || 'Unknown'}</td>
                        <td>${alert.rule ? alert.rule.name : 'ML Detection'}</td>
                        <td>${(alert.confidence * 100).toFixed(1)}%</td>
                        <td>${alert.status}</td>
                    `;
                    alertsTable.appendChild(row);
                });
            })
            .catch(error => console.error('Error loading alerts:', error));
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

    // Update charts with real data
    function updateCharts() {
        fetch('/api/statistics/')
            .then(response => response.json())
            .then(data => {
                // Update Category Chart
                const categoryData = {
                    labels: data.categories.map(cat => cat.attack_category),
                    datasets: [{
                        label: 'Alerts by Category',
                        data: data.categories.map(cat => cat.count),
                        backgroundColor: [
                            'rgba(255, 99, 132, 0.6)',
                            'rgba(54, 162, 235, 0.6)',
                            'rgba(255, 206, 86, 0.6)',
                            'rgba(75, 192, 192, 0.6)',
                            'rgba(153, 102, 255, 0.6)',
                            'rgba(255, 159, 64, 0.6)',
                        ],
                    }],
                };

                const categoriesChart = new Chart(document.getElementById('categoriesChart'), {
                    type: 'pie',
                    data: categoryData,
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'right' },
                            title: { display: true, text: 'Alerts by Attack Category' },
                        },
                    },
                });

                // Update Timeline Chart
                const timelineData = {
                    labels: data.timeline.map(t => new Date(t.timestamp).toLocaleTimeString()),
                    datasets: [{
                        label: 'Alerts',
                        data: data.timeline.map(t => t.count),
                        fill: false,
                        borderColor: 'rgb(75, 192, 192)',
                        tension: 0.1,
                    }],
                };

                const timelineChart = new Chart(document.getElementById('timelineChart'), {
                    type: 'line',
                    data: timelineData,
                    options: {
                        responsive: true,
                        scales: {
                            y: { beginAtZero: true, title: { display: true, text: 'Number of Alerts' } },
                            x: { title: { display: true, text: 'Time of Day' } },
                        },
                        plugins: {
                            title: { display: true, text: 'Alert Timeline (Last 24 Hours)' },
                        },
                    },
                });
            })
            .catch(error => console.error('Error loading stats:', error));
    }

    loadRecentAlerts();
    updateCharts();

    // Refresh data periodically
    setInterval(() => {
        loadRecentAlerts();
        updateCharts();
    }, 30000); // Refresh every 30 seconds
});