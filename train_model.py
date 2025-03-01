from sklearn.ensemble import RandomForestClassifier
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Load and prepare data (modify to your dataset path and preprocessing)
data = pd.read_csv('datasets/processed_data.csv')  # Path to your processed data file

# Prepare features and labels
X = data.drop(columns=['label'])  # Drop the target column
y = data['label']  # Target variable

# Save feature names for future use
feature_names = X.columns.tolist()

# Encode labels if necessary
label_encoder = LabelEncoder()
y = label_encoder.fit_transform(y)

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the Random Forest Classifier
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save the trained model and additional data
joblib.dump(model, 'trained_model.pkl')
joblib.dump(label_encoder, 'label_encoder.pkl')  # Save the label encoder
joblib.dump(feature_names, 'feature_names.pkl')  # Save feature names

print("Model training completed and saved as 'trained_model.pkl'.")
