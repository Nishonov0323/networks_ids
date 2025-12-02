# ids/views.py
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.core.files.storage import FileSystemStorage
from django.utils import timezone
from django.db.models import Count, Q
import pandas as pd
import joblib
from django.conf import settings
from .models import NetworkFlow, Alert, AlertRule
from datetime import datetime, timedelta


def dashboard(request):
    # Get recent flows
    flows = NetworkFlow.objects.all().order_by('-timestamp')[:10]
    
    # Get alert statistics
    total_alerts = Alert.objects.count()
    open_alerts = Alert.objects.filter(status='open').count()
    critical_alerts = Alert.objects.filter(severity='critical', status='open').count()
    
    # Get recent alerts (last 5)
    recent_alerts = Alert.objects.filter(status='open').order_by('-created_at')[:5]
    
    # Calculate prediction statistics from recent flows
    recent_predictions = flows.values_list('prediction', flat=True)
    benign_count = sum(1 for p in recent_predictions if p == 'Benign')
    malicious_count = len(recent_predictions) - benign_count
    
    # Get attack type distribution from recent alerts
    attack_distribution = Alert.objects.filter(
        created_at__gte=timezone.now() - timedelta(hours=24)
    ).values('attack_type').annotate(count=Count('id')).order_by('-count')[:5]
    
    context = {
        'flows': flows,
        'total_alerts': total_alerts,
        'open_alerts': open_alerts,
        'critical_alerts': critical_alerts,
        'recent_alerts': recent_alerts,
        'benign_count': benign_count,
        'malicious_count': malicious_count,
        'attack_distribution': attack_distribution,
    }
    return render(request, 'ids/dashboard.html', context)


def flows(request):
    flows = NetworkFlow.objects.all().order_by('-timestamp')
    context = {'flows': flows}
    return render(request, 'ids/flows.html', context)


def get_new_flows(request):
    latest_timestamp_str = request.GET.get('latest_timestamp', '')
    print(f"Received latest_timestamp: {latest_timestamp_str}")  # Debug log
    try:
        # If latest_timestamp is provided, parse it into a datetime object
        if latest_timestamp_str:
            latest_timestamp = datetime.strptime(latest_timestamp_str, '%Y-%m-%d %H:%M:%S')
            new_flows = NetworkFlow.objects.filter(timestamp__gt=latest_timestamp).order_by('-timestamp')
        else:
            new_flows = NetworkFlow.objects.all().order_by('-timestamp')[:10]
    except ValueError as e:
        # Handle invalid timestamp format
        print(f"Timestamp parsing error: {str(e)}")  # Debug log
        return JsonResponse({'error': f'Invalid timestamp format: {str(e)}. Expected format: YYYY-MM-DD HH:MM:SS'},
                            status=400)

    flows_data = [
        {
            'timestamp': str(flow.timestamp),
            'protocol': flow.protocol,
            'flow_duration': flow.flow_duration,
            'total_fwd_packets': flow.total_fwd_packets,
            'prediction': flow.prediction
        }
        for flow in new_flows
    ]
    return JsonResponse({'flows': flows_data})


def download_analysis(request):
    if request.method == 'POST':
        # Retrieve the analysis data from the session
        benign_count = request.session.get('benign_count', 0)
        other_counts = request.session.get('other_counts', {})
        total_predictions = request.session.get('total_predictions', 0)

        # Prepare the data for CSV
        data = [
            {'Category': 'Benign', 'Count': benign_count,
             'Percentage': (benign_count / total_predictions * 100) if total_predictions else 0}
        ]
        for label, count in other_counts.items():
            percentage = (count / total_predictions * 100) if total_predictions else 0
            data.append({'Category': label, 'Count': count, 'Percentage': percentage})

        # Create a DataFrame and generate CSV
        df = pd.DataFrame(data)
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="analysis_report.csv"'
        df.to_csv(path_or_buf=response, index=False)
        return response
    return HttpResponse(status=400)


def analysis(request):
    if request.method == 'POST' and request.FILES.get('csv_file'):
        # Handle file upload
        csv_file = request.FILES['csv_file']
        fs = FileSystemStorage()
        filename = fs.save(csv_file.name, csv_file)
        file_path = fs.path(filename)

        # Load the CSV file
        try:
            test_data = pd.read_csv(file_path)
        except Exception as e:
            fs.delete(filename)
            return render(request, 'ids/analysis.html', {'error': f'CSV faylni o\'qishda xatolik: {str(e)}'})

        # Load the model, scaler, and label encoder
        try:
            model = joblib.load(settings.BASE_DIR / 'ml_models/models/model.pkl')
            scaler = joblib.load(settings.BASE_DIR / 'ml_models/models/scaler.pkl')
            label_encoder = joblib.load(settings.BASE_DIR / 'ml_models/models/label_encoder.pkl')
        except Exception as e:
            fs.delete(filename)
            return render(request, 'ids/analysis.html', {'error': f'Modellarni yuklashda xatolik: {str(e)}. Iltimos, model fayllari mavjudligini tekshiring.'})

        # Preprocess the data and make predictions
        try:
            test_data = test_data.fillna(0)
            X_test = scaler.transform(test_data)
            predictions = model.predict(X_test)
            predicted_labels = label_encoder.inverse_transform(predictions)
        except Exception as e:
            fs.delete(filename)
            return render(request, 'ids/analysis.html', {'error': f'Ma\'lumotlarni qayta ishlashda xatolik: {str(e)}. CSV fayl formati to\'g\'ri ekanligini tekshiring.'})

        # Define known attack categories
        known_attacks = {
            'Port Scan', '(D)DOS', 'Web Attack', 'Botnet',
            'Brute Force', 'Infiltration', 'Heartbleed'
        }

        # Analyze the predictions
        prediction_counts = pd.Series(predicted_labels).value_counts().to_dict()
        total_predictions = len(predicted_labels)
        benign_count = prediction_counts.get('Benign', 0)

        # Separate known attacks and unknown attacks
        known_attack_counts = {}
        unknown_count = 0

        for label, count in prediction_counts.items():
            if label == 'Benign':
                continue
            if label in known_attacks:
                known_attack_counts[label] = count
            else:
                unknown_count += count

        # Create a copy for other_counts and add Unknown category if needed
        other_counts = dict(known_attack_counts)
        if unknown_count > 0:
            other_counts['Unknown'] = unknown_count

        # Calculate percentages
        benign_percentage = (benign_count / total_predictions * 100) if total_predictions else 0
        other_percentages = {
            label: (count / total_predictions * 100) if total_predictions else 0
            for label, count in other_counts.items()
        }

        # Identify top 3 attack types (excluding Benign)
        top_attacks = sorted(
            other_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:3]

        # Clean up the uploaded file
        fs.delete(filename)

        # Create alerts for detected attacks (optimized - one alert per attack type)
        alerts_created = 0
        unique_attacks = {}

        # Group predictions by attack type
        for i, prediction in enumerate(predicted_labels):
            if prediction != 'Benign':
                if prediction not in unique_attacks:
                    unique_attacks[prediction] = []
                # Store only first 5 samples of each attack type to avoid memory issues
                if len(unique_attacks[prediction]) < 5:
                    unique_attacks[prediction].append(i)

        # Create one alert per unique attack type
        for attack_type, sample_indices in unique_attacks.items():
            try:
                # Determine severity based on attack type
                severity = 'medium'  # default
                attack_lower = attack_type.lower()
                if 'ddos' in attack_lower or 'dos' in attack_lower:
                    severity = 'critical'
                elif 'botnet' in attack_lower or 'infiltration' in attack_lower or 'heartbleed' in attack_lower:
                    severity = 'critical'
                elif 'brute' in attack_lower:
                    severity = 'high'
                elif 'web' in attack_lower:
                    severity = 'medium'

                # Count total occurrences of this attack type
                attack_count = prediction_counts.get(attack_type, 0)

                # Create a single alert for this attack type
                alert = Alert.objects.create(
                    title=f"{attack_type} hujumi aniqlandi",
                    description=f"Yuklangan ma'lumotlarda {attack_count} ta {attack_type} hujumi aniqlandi. "
                                f"Bu tahlil jarayonida topilgan xavfli faoliyat.",
                    severity=severity,
                    attack_type=attack_type,
                    status='open'
                )
                alerts_created += 1

            except Exception as e:
                print(f"Alert yaratishda xatolik: {str(e)}")
                continue

        # Store data in session for download
        request.session['benign_count'] = benign_count
        request.session['other_counts'] = other_counts
        request.session['total_predictions'] = total_predictions

        # Pass the analysis to the template
        context = {
            'benign_count': benign_count,
            'benign_percentage': round(benign_percentage, 2),
            'other_counts': other_counts,
            'other_percentages': {label: round(pct, 2) for label, pct in other_percentages.items()},
            'total_predictions': total_predictions,
            'top_attacks': top_attacks,
            'alerts_created': alerts_created
        }
        return render(request, 'ids/analysis.html', context)

    return render(request, 'ids/analysis.html')


def alerts(request):
    """Alerts management page"""
    # Get filter parameters
    status_filter = request.GET.get('status', '')
    severity_filter = request.GET.get('severity', '')
    
    # Base queryset
    alerts_qs = Alert.objects.all()
    
    # Apply filters
    if status_filter:
        alerts_qs = alerts_qs.filter(status=status_filter)
    if severity_filter:
        alerts_qs = alerts_qs.filter(severity=severity_filter)
    
    # Get recent alerts (last 24 hours)
    recent_alerts = alerts_qs.order_by('-created_at')[:50]
    
    # Get alert statistics
    total_alerts = alerts_qs.count()
    open_alerts = alerts_qs.filter(status='open').count()
    critical_alerts = alerts_qs.filter(severity='critical', status='open').count()
    
    # Get alert counts by severity
    severity_stats = alerts_qs.values('severity').annotate(count=Count('id'))
    
    context = {
        'alerts': recent_alerts,
        'total_alerts': total_alerts,
        'open_alerts': open_alerts,
        'critical_alerts': critical_alerts,
        'severity_stats': severity_stats,
        'status_filter': status_filter,
        'severity_filter': severity_filter,
    }
    return render(request, 'ids/alerts.html', context)


def alert_detail(request, alert_id):
    """Alert detail and management"""
    alert = get_object_or_404(Alert, id=alert_id)
    
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'acknowledge':
            alert.status = 'acknowledged'
            alert.acknowledged_at = timezone.now()
            alert.save()
        elif action == 'resolve':
            alert.status = 'resolved'
            alert.resolved_at = timezone.now()
            alert.save()
        elif action == 'false_positive':
            alert.status = 'false_positive'
            alert.save()
        
        return JsonResponse({'status': 'success', 'new_status': alert.status})
    
    context = {'alert': alert}
    return render(request, 'ids/alert_detail.html', context)


def rules(request):
    """Rules management page"""
    rules = AlertRule.objects.all().order_by('-created_at')
    context = {'rules': rules}
    return render(request, 'ids/rules.html', context)


def create_alert_from_prediction(network_flow, prediction):
    """Helper function to create alerts based on ML predictions"""
    # Skip if prediction is Benign
    if prediction.lower() == 'benign':
        return None
    
    # Check if there are active rules for this attack type
    active_rules = AlertRule.objects.filter(
        is_active=True,
        attack_types__contains=[prediction]
    )
    
    if not active_rules.exists():
        # Create a default rule for unknown attack types
        rule, created = AlertRule.objects.get_or_create(
            name=f"Default rule for {prediction}",
            defaults={
                'description': f"Automatically created rule for {prediction} attacks",
                'attack_types': [prediction],
                'min_severity_score': 0.7,
            }
        )
    
    # Determine severity based on attack type
    severity_mapping = {
        'ddos': 'critical',
        'dos': 'high',
        'botnet': 'critical',
        'brute_force': 'high',
        'infiltration': 'critical',
        'web_attack': 'medium',
        'heartbleed': 'critical',
    }
    
    severity = 'medium'  # default
    for attack_pattern, attack_severity in severity_mapping.items():
        if attack_pattern.lower() in prediction.lower():
            severity = attack_severity
            break
    
    # Create the alert
    alert = Alert.objects.create(
        title=f"{prediction} Attack Detected",
        description=f"Suspicious {prediction} activity detected in network traffic",
        severity=severity,
        network_flow=network_flow,
        attack_type=prediction,
        status='open'
    )
    
    return alert