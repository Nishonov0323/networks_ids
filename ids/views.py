# ids/views.py
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
from django.core.files.storage import FileSystemStorage
import pandas as pd
import joblib
from django.conf import settings
from .models import NetworkFlow
from datetime import datetime


def dashboard(request):
    flows = NetworkFlow.objects.all().order_by('-timestamp')[:10]
    context = {'flows': flows}
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
            'top_attacks': top_attacks
        }
        return render(request, 'ids/analysis.html', context)

    return render(request, 'ids/analysis.html')