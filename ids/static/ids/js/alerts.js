// ids/static/ids/js/alerts.js
document.addEventListener('DOMContentLoaded', () => {
    console.log('Alerts page loaded');
    
    // Auto-refresh alerts every 30 seconds
    setInterval(() => {
        if (document.querySelector('.main-content')) {
            // Only refresh if user hasn't interacted recently
            const lastActivity = localStorage.getItem('lastActivity');
            const now = Date.now();
            if (!lastActivity || (now - parseInt(lastActivity)) > 25000) {
                location.reload();
            }
        }
    }, 30000);
    
    // Track user activity
    document.addEventListener('click', () => {
        localStorage.setItem('lastActivity', Date.now());
    });
    
    document.addEventListener('scroll', () => {
        localStorage.setItem('lastActivity', Date.now());
    });
    
    // Add confirmation for alert actions
    window.updateAlertStatus = function(alertId, action) {
        let confirmMessage = '';
        switch(action) {
            case 'acknowledge':
                confirmMessage = 'Bu ogohlantirishni qabul qilishni tasdiqlaysizmi?';
                break;
            case 'resolve':
                confirmMessage = 'Bu ogohlantirishni hal qilingan deb belgilashni tasdiqlaysizmi?';
                break;
            case 'false_positive':
                confirmMessage = 'Bu ogohlantirishni noto\'g\'ri signal deb belgilashni tasdiqlaysizmi?';
                break;
        }
        
        if (confirm(confirmMessage)) {
            fetch(`/alerts/${alertId}/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
                },
                body: `action=${action}`
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    location.reload();
                } else {
                    alert('Xatolik yuz berdi');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Xatolik yuz berdi');
            });
        }
    };
});