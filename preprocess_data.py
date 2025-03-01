import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# Dataset column names
col_names = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
             "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", 
             "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", 
             "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", 
             "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", 
             "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", 
             "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", 
             "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", 
             "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", 
             "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty_level"]

# Load the dataset
data = pd.read_csv(r"C:\Users\Ashwi\OneDrive\Desktop\IDS Project\dataset\KDDTrain+.txt", header=None, names=col_names)

# Drop unnecessary columns
data.drop(['difficulty_level'], axis=1, inplace=True)

# Encode categorical columns
cat_cols = ['protocol_type', 'service', 'flag']  # List of categorical columns
encoder = LabelEncoder()
for col in cat_cols:
    data[col] = encoder.fit_transform(data[col])

# Normalize numeric columns
numeric_cols = data.select_dtypes(include=np.number).columns
scaler = StandardScaler()
data[numeric_cols] = scaler.fit_transform(data[numeric_cols])

# Encode the label column (binary classification: 0 for normal, 1 for attack)
label_encoder = LabelEncoder()
data['label'] = label_encoder.fit_transform(data['label'])

# Save the preprocessed dataset
data.to_csv('./datasets/processed_data.csv', index=False)

# Save label encoders for future use

joblib.dump(encoder, './datasets/label_encoder.pkl')  # For categorical columns encoding
joblib.dump(label_encoder, './datasets/label_encoder_classes.pkl')  # For label encoding

print("Preprocessing completed and dataset saved!")
