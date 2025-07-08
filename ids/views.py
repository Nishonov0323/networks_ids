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
            return render(request, 'ids/analysis.html', {'error': f'Error reading CSV file: {str(e)}'})

        # Load the model, scaler, and label encoder
        model = joblib.load(settings.BASE_DIR / 'ml_models/models/model.pkl')
        scaler = joblib.load(settings.BASE_DIR / 'ml_models/models/scaler.pkl')
        label_encoder = joblib.load(settings.BASE_DIR / 'ml_models/models/label_encoder.pkl')

        # Preprocess the data
        test_data = test_data.fillna(0)
        X_test = scaler.transform(test_data)

        # Make predictions
        predictions = model.predict(X_test)
        predicted_labels = label_encoder.inverse_transform(predictions)

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

        # Add Unknown category if there are any unknown labels
        other_counts = known_attack_counts
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

        # Create alerts for detected attacks
        alerts_created = 0
        for i, prediction in enumerate(predicted_labels):
            if prediction != 'Benign':
                # Create a dummy NetworkFlow object for the alert
                # In a real scenario, you would have actual network flow data
                try:
                    # Create a basic network flow entry
                    network_flow = NetworkFlow.objects.create(
                        protocol=test_data.iloc[i].get('Protocol', 0),
                        flow_duration=test_data.iloc[i].get('Flow Duration', 0),
                        total_fwd_packets=test_data.iloc[i].get('Total Fwd Packets', 0),
                        total_backward_packets=test_data.iloc[i].get('Total Backward Packets', 0),
                        fwd_packets_length_total=test_data.iloc[i].get('Fwd Packets Length Total', 0),
                        bwd_packets_length_total=test_data.iloc[i].get('Bwd Packets Length Total', 0),
                        fwd_packet_length_max=test_data.iloc[i].get('Fwd Packet Length Max', 0),
                        fwd_packet_length_min=test_data.iloc[i].get('Fwd Packet Length Min', 0),
                        fwd_packet_length_mean=test_data.iloc[i].get('Fwd Packet Length Mean', 0),
                        fwd_packet_length_std=test_data.iloc[i].get('Fwd Packet Length Std', 0),
                        bwd_packet_length_max=test_data.iloc[i].get('Bwd Packet Length Max', 0),
                        bwd_packet_length_min=test_data.iloc[i].get('Bwd Packet Length Min', 0),
                        bwd_packet_length_mean=test_data.iloc[i].get('Bwd Packet Length Mean', 0),
                        bwd_packet_length_std=test_data.iloc[i].get('Bwd Packet Length Std', 0),
                        flow_bytes_s=test_data.iloc[i].get('Flow Bytes/s', 0),
                        flow_packets_s=test_data.iloc[i].get('Flow Packets/s', 0),
                        flow_iat_mean=test_data.iloc[i].get('Flow IAT Mean', 0),
                        flow_iat_std=test_data.iloc[i].get('Flow IAT Std', 0),
                        flow_iat_max=test_data.iloc[i].get('Flow IAT Max', 0),
                        flow_iat_min=test_data.iloc[i].get('Flow IAT Min', 0),
                        fwd_iat_total=test_data.iloc[i].get('Fwd IAT Total', 0),
                        fwd_iat_mean=test_data.iloc[i].get('Fwd IAT Mean', 0),
                        fwd_iat_std=test_data.iloc[i].get('Fwd IAT Std', 0),
                        fwd_iat_max=test_data.iloc[i].get('Fwd IAT Max', 0),
                        fwd_iat_min=test_data.iloc[i].get('Fwd IAT Min', 0),
                        bwd_iat_total=test_data.iloc[i].get('Bwd IAT Total', 0),
                        bwd_iat_mean=test_data.iloc[i].get('Bwd IAT Mean', 0),
                        bwd_iat_std=test_data.iloc[i].get('Bwd IAT Std', 0),
                        bwd_iat_max=test_data.iloc[i].get('Bwd IAT Max', 0),
                        bwd_iat_min=test_data.iloc[i].get('Bwd IAT Min', 0),
                        fwd_psh_flags=test_data.iloc[i].get('Fwd PSH Flags', 0),
                        fwd_header_length=test_data.iloc[i].get('Fwd Header Length', 0),
                        bwd_header_length=test_data.iloc[i].get('Bwd Header Length', 0),
                        fwd_packets_s=test_data.iloc[i].get('Fwd Packets/s', 0),
                        bwd_packets_s=test_data.iloc[i].get('Bwd Packets/s', 0),
                        packet_length_min=test_data.iloc[i].get('Packet Length Min', 0),
                        packet_length_max=test_data.iloc[i].get('Packet Length Max', 0),
                        packet_length_mean=test_data.iloc[i].get('Packet Length Mean', 0),
                        packet_length_std=test_data.iloc[i].get('Packet Length Std', 0),
                        packet_length_variance=test_data.iloc[i].get('Packet Length Variance', 0),
                        fin_flag_count=test_data.iloc[i].get('FIN Flag Count', 0),
                        syn_flag_count=test_data.iloc[i].get('SYN Flag Count', 0),
                        rst_flag_count=test_data.iloc[i].get('RST Flag Count', 0),
                        psh_flag_count=test_data.iloc[i].get('PSH Flag Count', 0),
                        ack_flag_count=test_data.iloc[i].get('ACK Flag Count', 0),
                        urg_flag_count=test_data.iloc[i].get('URG Flag Count', 0),
                        ece_flag_count=test_data.iloc[i].get('ECE Flag Count', 0),
                        down_up_ratio=test_data.iloc[i].get('Down/Up Ratio', 0),
                        avg_packet_size=test_data.iloc[i].get('Average Packet Size', 0),
                        avg_fwd_segment_size=test_data.iloc[i].get('Avg Fwd Segment Size', 0),
                        avg_bwd_segment_size=test_data.iloc[i].get('Avg Bwd Segment Size', 0),
                        subflow_fwd_packets=test_data.iloc[i].get('Subflow Fwd Packets', 0),
                        subflow_fwd_bytes=test_data.iloc[i].get('Subflow Fwd Bytes', 0),
                        subflow_bwd_packets=test_data.iloc[i].get('Subflow Bwd Packets', 0),
                        subflow_bwd_bytes=test_data.iloc[i].get('Subflow Bwd Bytes', 0),
                        init_fwd_win_bytes=test_data.iloc[i].get('Init Fwd Win Bytes', 0),
                        init_bwd_win_bytes=test_data.iloc[i].get('Init Bwd Win Bytes', 0),
                        fwd_act_data_packets=test_data.iloc[i].get('Fwd Act Data Packets', 0),
                        fwd_seg_size_min=test_data.iloc[i].get('Fwd Seg Size Min', 0),
                        active_mean=test_data.iloc[i].get('Active Mean', 0),
                        active_std=test_data.iloc[i].get('Active Std', 0),
                        active_max=test_data.iloc[i].get('Active Max', 0),
                        active_min=test_data.iloc[i].get('Active Min', 0),
                        idle_mean=test_data.iloc[i].get('Idle Mean', 0),
                        idle_std=test_data.iloc[i].get('Idle Std', 0),
                        idle_max=test_data.iloc[i].get('Idle Max', 0),
                        idle_min=test_data.iloc[i].get('Idle Min', 0),
                        prediction=prediction
                    )
                    
                    # Create alert for this detection
                    alert = create_alert_from_prediction(network_flow, prediction)
                    if alert:
                        alerts_created += 1
                        
                except Exception as e:
                    # If we can't create full NetworkFlow, just create a simpler alert
                    alert = Alert.objects.create(
                        title=f"{prediction} Attack Detected",
                        description=f"Suspicious {prediction} activity detected in uploaded data",
                        severity='medium',
                        attack_type=prediction,
                        status='open'
                    )
                    alerts_created += 1

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