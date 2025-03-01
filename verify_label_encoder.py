import joblib

# Load the saved LabelEncoder
label_encoder = joblib.load('./datasets/label_encoder_classes.pkl')

# Print all classes in the LabelEncoder
print("Classes in LabelEncoder:", label_encoder.classes_)

# Test decoding a sample label
numeric_label = 11  # Replace with any numeric prediction you want to test
decoded_label = label_encoder.inverse_transform([numeric_label])

print(f"The decoded label for {numeric_label} is: {decoded_label[0]}")


