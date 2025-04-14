import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import joblib
import os


# Step 1: Load and preprocess the training data (test.csv)
def load_and_preprocess_data(file_path):
    # Load the dataset
    data = pd.read_csv(file_path)

    # Handle missing values (if any)
    data = data.fillna(0)

    # Separate features and target
    X = data.drop('Y', axis=1)
    y = data['Y']

    # Encode the target variable (Y)
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # Scale the features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y_encoded, scaler, label_encoder


# Step 2: Train the model
def train_model(X, y):
    # Split the data into training and validation sets
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train a Random Forest Classifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Print validation accuracy (optional)
    val_accuracy = model.score(X_val, y_val)
    print(f"Validation Accuracy: {val_accuracy:.4f}")

    return model


# Step 3: Save the model, scaler, and label encoder
def save_artifacts(model, scaler, label_encoder, model_path, scaler_path, encoder_path):
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    joblib.dump(label_encoder, encoder_path)
    print("Model and preprocessing artifacts saved.")


# Step 4: Load and preprocess the test data (test_x.csv), then predict
def predict_on_test_data(test_file_path, model_path, scaler_path, encoder_path, output_path):
    # Load the saved model, scaler, and label encoder
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    label_encoder = joblib.load(encoder_path)

    # Load the test data
    test_data = pd.read_csv(test_file_path)

    # Handle missing values
    test_data = test_data.fillna(0)

    # Scale the test data
    X_test = scaler.transform(test_data)

    # Make predictions
    predictions = model.predict(X_test)

    # Decode the predictions back to labels
    predicted_labels = label_encoder.inverse_transform(predictions)

    # Save the predictions to a CSV file
    output_df = pd.DataFrame({
        'Prediction': predicted_labels
    })
    output_df.to_csv(output_path, index=False)
    print(f"Predictions saved to {output_path}")


# Main function to orchestrate the process
def main():
    # File paths
    train_file_path = 'data/test.csv'  # Path to your training data
    test_file_path = 'data/test_x.csv'  # Path to your test data
    model_path = 'models/model.pkl'
    scaler_path = 'models/scaler.pkl'
    encoder_path = 'models/label_encoder.pkl'
    output_path = 'data_predict/predictions.csv'  # Path to save predictions

    # Create directories if they don't exist
    os.makedirs('models', exist_ok=True)
    os.makedirs('data_predict', exist_ok=True)

    # Step 1: Load and preprocess training data
    X, y, scaler, label_encoder = load_and_preprocess_data(train_file_path)

    # Step 2: Train the model
    model = train_model(X, y)

    # Step 3: Save the model and preprocessing artifacts
    save_artifacts(model, scaler, label_encoder, model_path, scaler_path, encoder_path)

    # Step 4: Predict on test data and save the results
    predict_on_test_data(test_file_path, model_path, scaler_path, encoder_path, output_path)


if __name__ == "__main__":
    main()
