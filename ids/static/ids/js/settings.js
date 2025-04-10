document.addEventListener('DOMContentLoaded', () => {
    const interfacesTable = document.getElementById('interfacesTable');
    const settingsForm = document.getElementById('systemSettings');

    function loadInterfaces() {
        fetch('/api/interfaces/')
            .then(response => response.json())
            .then(data => {
                interfacesTable.innerHTML = '';
                data.results.forEach(interface => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${interface.name}</td>
                        <td>${interface.interface_type}</td>
                        <td>${interface.ip_address || 'N/A'}</td>
                        <td>${interface.is_monitoring ? 'Yes' : 'No'}</td>
                        <td>
                            <button class="btn btn-sm btn-${interface.is_monitoring ? 'danger' : 'success'} toggle-monitoring" data-id="${interface.id}">
                                ${interface.is_monitoring ? 'Stop' : 'Start'}
                            </button>
                        </td>
                    `;
                    interfacesTable.appendChild(row);
                });

                document.querySelectorAll('.toggle-monitoring').forEach(btn => {
                    btn.addEventListener('click', () => toggleMonitoring(btn.dataset.id));
                });
            })
            .catch(error => console.error('Error loading interfaces:', error));
    }

    function toggleMonitoring(interfaceId) {
        fetch(`/api/interfaces/${interfaceId}/toggle_monitoring/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken'),
            },
        })
            .then(response => response.json())
            .then(data => {
                loadInterfaces();
            })
            .catch(error => console.error('Error toggling monitoring:', error));
    }

    settingsForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const flowTimeout = document.getElementById('flowTimeout').value;
        const alertRetention = document.getElementById('alertRetention').value;

        // In a real app, you'd send this to the backend to update settings
        console.log('Settings saved:', { flowTimeout, alertRetention });
        alert('Settings saved (placeholder)');
    });

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

    loadInterfaces();
});