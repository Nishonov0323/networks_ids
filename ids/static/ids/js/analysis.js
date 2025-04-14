// ids/static/ids/js/analysis.js
document.addEventListener('DOMContentLoaded', () => {
    // Show loading message when form is submitted
    const form = document.getElementById('uploadForm');
    const loadingDiv = document.getElementById('loading');

    if (form && loadingDiv) {
        form.addEventListener('submit', () => {
            loadingDiv.style.display = 'block';
        });
    }

    // Check if the chart data is available
    if (typeof benignCount !== 'undefined' && typeof otherCounts !== 'undefined') {
        const labels = ['Benign', ...Object.keys(otherCounts)];
        const data = [benignCount, ...Object.values(otherCounts)];

        // Dynamically generate colors for the chart
        const colors = labels.map((label, index) => {
            if (label === 'Unknown') {
                return '#dc3545'; // Red for Unknown
            }
            const hue = (index * 137.508) % 360; // Golden angle approximation for distinct colors
            return `hsl(${hue}, 70%, 50%)`;
        });

        // Chart configuration options
        const chartOptions = {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
                title: { display: true, text: 'Prediction Distribution' },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.dataset.data.reduce((sum, val) => sum + val, 0);
                            const percentage = ((value / total) * 100).toFixed(2);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        };

        // Donut Chart
        const donutCtx = document.getElementById('donutChart').getContext('2d');
        new Chart(donutCtx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderWidth: 1
                }]
            },
            options: chartOptions
        });

        // Bar Chart
        const barCtx = document.getElementById('barChart').getContext('2d');
        new Chart(barCtx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Count',
                    data: data,
                    backgroundColor: colors,
                    borderWidth: 1
                }]
            },
            options: {
                ...chartOptions,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: { display: true, text: 'Count' }
                    },
                    x: {
                        title: { display: true, text: 'Category' }
                    }
                }
            }
        });

        // Chart Toggle Functionality
        const toggleButtons = document.querySelectorAll('.toggle-btn');
        const donutChart = document.getElementById('donutChart');
        const barChart = document.getElementById('barChart');

        toggleButtons.forEach(button => {
            button.addEventListener('click', () => {
                toggleButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');

                const chartType = button.getAttribute('data-chart');
                if (chartType === 'donut') {
                    donutChart.style.display = 'block';
                    barChart.style.display = 'none';
                } else {
                    donutChart.style.display = 'none';
                    barChart.style.display = 'block';
                }
            });
        });
    }
});