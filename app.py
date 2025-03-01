import os
import json
import logging
import datetime
import base64
import joblib
import hashlib
import numpy as np
import pandas as pd
import jwt
import bcrypt
from scapy.all import sniff, IP, TCP, UDP
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
from pymongo import MongoClient
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from functools import wraps
import time
from threading import Thread
from flask_cors import CORS
from datetime import timezone
import pytz
import psutil
from flask_jwt_extended import jwt_required, get_jwt_identity



# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_default_secret_key'

# Enable CORS for frontend-backend communication
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="http://localhost:5173")


def send_real_time_alert(alert_type, message, details=None):
    alert = {
        "timestamp": datetime.datetime.now(pytz.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p'),
        "type": alert_type,
        "message": message,
        "details": details
    }
    logging.info(f"Sending real-time alert: {alert}")  # Add this line for debugging
    socketio.emit('real_time_alert', alert)
    logging.info(f"Real-time alert sent: {alert}")



# Load secret key for JWT
SECRET_KEY = os.getenv('SECRET_KEY', 'your_default_secret_key')

# MongoDB connection setup
client = MongoClient("mongodb://localhost:27017/")
db = client['ids_database']
users_collection = db['users']

# Paths to required files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, 'trained_model.pkl')
LABEL_ENCODER_PATH = os.path.join(BASE_DIR, 'label_encoder.pkl')
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, 'private.key')

# Load model and label encoder
model = joblib.load(MODEL_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)

# Feature extraction function for 41 features
def extract_features(packet):
    """
    Extract features from a network packet to match the model's input schema.
    """
    features = {
        'duration': 0, 'protocol_type': 0, 'service': 0, 'flag': 0, 'src_bytes': 0, 'dst_bytes': 0, 'land': 0,
        'wrong_fragment': 0, 'urgent': 0, 'hot': 0, 'num_failed_logins': 0, 'logged_in': 0, 'num_compromised': 0,
        'root_shell': 0, 'su_attempted': 0, 'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
        'num_access_files': 0, 'num_outbound_cmds': 0, 'is_host_login': 0, 'is_guest_login': 0, 'count': 0,
        'srv_count': 0, 'serror_rate': 0, 'srv_serror_rate': 0, 'rerror_rate': 0, 'srv_rerror_rate': 0,
        'same_srv_rate': 0, 'diff_srv_rate': 0, 'srv_diff_host_rate': 0, 'dst_host_count': 0, 'dst_host_srv_count': 0,
        'dst_host_same_srv_rate': 0, 'dst_host_diff_srv_rate': 0, 'dst_host_same_src_port_rate': 0,
        'dst_host_srv_diff_host_rate': 0, 'dst_host_serror_rate': 0, 'dst_host_srv_serror_rate': 0,
        'dst_host_rerror_rate': 0, 'dst_host_srv_rerror_rate': 0
    }

    if IP in packet:
        features['protocol_type'] = packet[IP].proto  # Protocol (e.g., 6 = TCP, 17 = UDP)
        features['src_bytes'] = len(packet[IP])  # Bytes sent
        features['dst_bytes'] = len(packet) - len(packet[IP])  # Remaining bytes (approx. bytes received)
        features['flag'] = 1 if TCP in packet else 0  # Example: TCP packets have a flag
        features['land'] = 1 if packet[IP].src == packet[IP].dst else 0  # Same source and destination IP

    # Convert to a pandas DataFrame with proper feature names
    features_df = pd.DataFrame([features])
    return features_df

# Global dictionary to track last alert time
last_alert_time = {}

# Real-time alert sending
def send_real_time_alert(alert_type, message, details=None):
    global last_alert_time

    # Throttle interval in seconds
    throttle_interval = 5
    current_time = datetime.datetime.now()

    # Only send an alert if the last one for the same type was sent outside the throttle interval
    if alert_type not in last_alert_time or (current_time - last_alert_time[alert_type]).total_seconds() > throttle_interval:
        last_alert_time[alert_type] = current_time
        alert = {
            "timestamp": current_time.astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p'),
            "type": alert_type,
            "message": message,
            "details": details
        }
        socketio.emit('real-time-alert', alert)
        logging.info(f"Real-time alert sent: {alert}")

# Real-time prediction
def predict_packet(packet):
    try:
        # Extract features and reshape for prediction
        features = extract_features(packet)
        prediction = model.predict(features)
        label = label_mapping.get(int(prediction[0]), "Unknown")

        # Detailed packet info
        packet_info = {
            "src_ip": packet[IP].src if IP in packet else "Unknown",
            "dst_ip": packet[IP].dst if IP in packet else "Unknown",
            "protocol": packet[IP].proto if IP in packet else "Unknown",
            "length": len(packet),
            "summary": packet.summary()
        }

        # Log the prediction
        logging.info(f"Prediction: {label}")
        emit_real_time_data(packet_info, label)

        # Send alerts for anomalies
        if label != "Normal":
            send_real_time_alert(
                alert_type="Intrusion Detected",
                message=f"Potential intrusion detected: {label}",
                details=packet_info
            )
    except Exception as e:
        logging.error(f"Error during prediction: {e}")

# Send real-time data to frontend
def emit_real_time_data(packet_info, label):
    ist_tz = pytz.timezone('Asia/Kolkata')
    current_time_utc = datetime.datetime.now(pytz.utc)
    current_time_ist = current_time_utc.astimezone(ist_tz).strftime('%Y-%m-%d %I:%M:%S %p')

    data = {
        "timestamp": current_time_ist,
        "src_ip": packet_info["src_ip"],
        "dst_ip": packet_info["dst_ip"],
        "protocol": packet_info["protocol"],
        "length": packet_info["length"],
        "summary": packet_info["summary"],
        "prediction": label,
    }

    socketio.emit('real-time-data', data)

# Packet capture function
def capture_packets(interface):
    """
    Capture packets in real-time and analyze them.
    """
    logging.info(f"Starting packet capture on interface: {interface}")
    sniff(iface=interface, prn=predict_packet, store=False)

# Flask endpoint to start packet capture
@app.route('/start-packet-capture', methods=['POST'])
def start_packet_capture():
    interface = request.json.get('interface', 'eth0')  # Default to 'eth0' if no interface is provided
    thread = Thread(target=capture_packets, args=(interface,))
    thread.daemon = True
    thread.start()
    return jsonify({"message": f"Packet capture started on interface {interface}"}), 200

# Function to extract features and predict attack type
def emit_real_time_packet(packet):
    if IP in packet:
        # Extract packet features
        features = extract_features(packet)

        # Predict attack type using the trained model
        try:
            prediction = model.predict(features)
            label = label_mapping.get(int(prediction[0]), "Unknown")
        except Exception as e:
            label = "Prediction Error"
            logging.error(f"Prediction error: {e}")

        # Construct the packet data
        packet_data = {
            "timestamp": datetime.datetime.now(pytz.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p'),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Other",
            "length": len(packet),
            "prediction": label  # Include prediction in real-time data
        }

        # Send real-time data to frontend
        socketio.emit('real-time-packet', packet_data)
        logging.info(f"Real-time packet with prediction sent: {packet_data}")

# Start network packet capture
def capture_packets(interface):
    logging.info(f"Starting packet capture on {interface}")
    sniff(iface=interface, prn=emit_real_time_packet, store=False)

# WebSocket event for real-time alerts
@socketio.on('connect')
def handle_connect():
    logging.info("Client connected to WebSocket.")
    emit('server_message', {'message': 'Connected to server'})



# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(BASE_DIR, 'app.log'))
    ]
)

# Function to anonymize sensitive data
def anonymize_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

# JWT functions
def generate_jwt(user_id, role):
    expiration_time = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    token = jwt.encode({'user_id': user_id, 'role': role, 'exp': expiration_time}, SECRET_KEY, algorithm='HS256')
    logging.info(f"JWT generated for user {anonymize_data(user_id)} with role {role}.")
    return token
    

def log_activity(user_id, action, details=""):
    timestamp = datetime.datetime.now(pytz.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p')
    activity_log = {
        "user_id": user_id,
        "action": action,
        "timestamp": timestamp,
        "details": details
    }
    db.activity_logs.insert_one(activity_log)
    logging.info(f"Activity logged for user {user_id}: {action} at {timestamp}")

# Function to send real-time alerts
def send_real_time_alert(alert_type, message, details=None):
    alert = {
        "timestamp": datetime.datetime.now(pytz.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p'),
        "type": alert_type,
        "message": message,
        "details": details
    }
    socketio.emit('real_time_alert', alert)
    logging.info(f"Real-time alert sent: {alert}")

# Function to monitor system performance
def monitor_system_performance():
    # Get CPU and memory usage
    cpu_usage = psutil.cpu_percent(interval=1)  # 1 second interval
    memory_usage = psutil.virtual_memory().percent

    # Define thresholds for performance alert (you can adjust these thresholds)
    if cpu_usage > 85:
        send_real_time_alert(
            alert_type="System Performance Issue",
            message=f"High CPU usage detected: {cpu_usage}%",
            details="Server is under heavy load"
        )
    if memory_usage > 85:
        send_real_time_alert(
            alert_type="System Performance Issue",
            message=f"High memory usage detected: {memory_usage}%",
            details="Server is running out of memory"
        )

def start_performance_monitoring():
    while True:
        monitor_system_performance()
        time.sleep(10)  # Sleep for 10 seconds before checking again

# Start the performance monitoring in a background thread
performance_thread = Thread(target=start_performance_monitoring)
performance_thread.daemon = True  # Daemonize the thread
performance_thread.start()



def verify_jwt(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        logging.warning("JWT expired.")
        return None
    except jwt.InvalidTokenError:
        logging.warning("Invalid JWT.")
        return None

# RSA key functions
def load_private_key():
    with open(PRIVATE_KEY_PATH, 'r') as f:
        return RSA.import_key(f.read())

def decrypt_aes_key(private_key, encrypted_aes_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(base64.b64decode(encrypted_aes_key))

def decrypt_features(aes_key, nonce, ciphertext, tag):
    # Ensure all inputs are byte arrays (decode if needed)
    nonce_bytes = base64.b64decode(nonce) if isinstance(nonce, str) else nonce
    ciphertext_bytes = base64.b64decode(ciphertext) if isinstance(ciphertext, str) else ciphertext
    tag_bytes = base64.b64decode(tag) if isinstance(tag, str) else tag

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce_bytes)
    decrypted_data = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
    
    # Convert the decrypted data back to a dictionary or DataFrame as needed
    features = json.loads(decrypted_data)
    feature_names = [f'feature_{i}' for i in range(len(features))]
    return pd.DataFrame([features], columns=feature_names)



# Load model and label encoder
model = joblib.load(MODEL_PATH)
label_encoder = joblib.load(LABEL_ENCODER_PATH)

# Label mapping
label_mapping = {
    0: "DoS - back", 1: "U2R - buffer_overflow", 2: "R2L - ftp_write", 3: "R2L - guess_passwd",
    5: "Probe - ipsweep", 9: "DoS - neptune", 10: "Probe - nmap", 11: "Normal",
    15: "Probe - portsweep", 17: "Probe - satan", 18: "DoS - smurf", 21: "R2L - warezclient",
}

# Role-Based Access Control Decorator
def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization', '').split(" ")[1]
            decoded = verify_jwt(token)
            if not decoded or decoded.get('role') != role:
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Admin routes
@app.route('/admin', methods=['GET'])
@role_required('admin')
def admin_dashboard():
    logging.info("Admin dashboard accessed.")
    return jsonify({"message": "Welcome to the admin dashboard."})

@app.route('/admin/users', methods=['GET'])
@role_required('admin')
def get_all_users():
    try:
        # Fetch users from the collection
        users = list(users_collection.find({}, {"_id": 0}))

        # Convert binary password field to base64 (or any other binary fields)
        for user in users:
            if 'password' in user:
                user['password'] = base64.b64encode(user['password']).decode('utf-8')

        return jsonify({"users": users})

    except Exception as e:
        app.logger.error(f"Error fetching users: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin/create_user', methods=['POST'])
@role_required('admin')
def create_user():
    user_data = request.json
    user_id = user_data.get('user_id')
    password = user_data.get('password')
    role = user_data.get('role', 'user')

    if users_collection.find_one({"user_id": user_id}):
        return jsonify({"error": "User already exists."}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users_collection.insert_one({"user_id": user_id, "role": role, "password": hashed_password})
    return jsonify({"message": f"User {user_id} created with role {role}."}), 201

def log_activity(user_id, action, details=""):
    timestamp = datetime.datetime.now(pytz.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p')
    activity_log = {
        "user_id": user_id,
        "action": action,
        "timestamp": timestamp,
        "details": details
    }
    db.activity_logs.insert_one(activity_log)

@app.route('/admin/update_user_role', methods=['POST'])
@role_required('admin')
def update_user_role():
    user_data = request.json
    user_id = user_data.get('user_id')
    new_role = user_data.get('role')

    result = users_collection.update_one({"user_id": user_id}, {"$set": {"role": new_role}})
    if result.matched_count == 0:
        return jsonify({"error": f"User {user_id} not found."}), 404

    # Log role update activity
    log_activity(user_id, "Role Update", f"Role updated to {new_role}")
    
    return jsonify({"message": f"User {user_id}'s role updated to {new_role}."})


@app.route('/admin/delete_user', methods=['POST'])
@role_required('admin')
def delete_user():
    user_data = request.json
    user_id = user_data.get('user_id')

    result = users_collection.delete_one({"user_id": user_id})
    if result.deleted_count == 0:
        return jsonify({"error": f"User {user_id} not found."}), 404

    # Log user deletion activity
    log_activity(user_id, "User Deletion", f"User {user_id} deleted.")
    
    return jsonify({"message": f"User {user_id} has been deleted."})

@app.route('/admin/login_history', methods=['GET'])
@role_required('admin')
def get_login_history():
    try:
        # Fetch the most recent login history entries (you can limit or sort them as needed)
        login_history = list(db.user_login_history.find({}, {"_id": 0}).sort("timestamp", -1).limit(50))  # Sort by timestamp descending, limit to 10

        return jsonify({"login_history": login_history})

    except Exception as e:
        app.logger.error(f"Error fetching login history: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500
    
@app.route('/admin/activity_logs', methods=['GET'])
@role_required('admin')
def get_activity_logs():
    try:
        # Fetch the most recent activity logs (you can limit or sort them as needed)
        activity_logs = list(db.activity_logs.find({}, {"_id": 0}).sort("timestamp", -1).limit(10))  # Sort by timestamp descending, limit to 10

        return jsonify({"activity_logs": activity_logs})

    except Exception as e:
        app.logger.error(f"Error fetching activity logs: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route('/admin/bulk_actions', methods=['POST'])
@role_required('admin')
def bulk_actions():
    try:
        actions = request.json.get('actions', [])
        results = []

        for action in actions:
            user_id = action.get('user_id')
            operation = action.get('operation')
            details = action.get('details', {})

            if operation == "delete":
                result = users_collection.delete_one({"user_id": user_id})
                if result.deleted_count > 0:
                    log_activity(user_id, "Bulk Deletion", "User deleted via bulk action.")
                    results.append({"user_id": user_id, "status": "deleted"})
                else:
                    results.append({"user_id": user_id, "status": "not found"})

            elif operation == "update_role":
                new_role = details.get('role')
                result = users_collection.update_one({"user_id": user_id}, {"$set": {"role": new_role}})
                if result.matched_count > 0:
                    log_activity(user_id, "Bulk Role Update", f"Role updated to {new_role} via bulk action.")
                    results.append({"user_id": user_id, "status": f"role updated to {new_role}"})
                else:
                    results.append({"user_id": user_id, "status": "not found"})

            elif operation == "suspend":
                result = users_collection.update_one({"user_id": user_id}, {"$set": {"suspended": True}})
                if result.matched_count > 0:
                    log_activity(user_id, "Suspension", "User suspended via bulk action.")
                    results.append({"user_id": user_id, "status": "suspended"})
                else:
                    results.append({"user_id": user_id, "status": "not found"})

            elif operation == "unsuspend":
                result = users_collection.update_one({"user_id": user_id}, {"$set": {"suspended": False}})
                if result.matched_count > 0:
                    log_activity(user_id, "Unsuspension", "User unsuspended via bulk action.")
                    results.append({"user_id": user_id, "status": "unsuspended"})
                else:
                    results.append({"user_id": user_id, "status": "not found"})

            elif operation == "add_user":
                # Ensure that all required details (e.g., password, role) are provided
                new_user_data = details.get('user_data')
                if not new_user_data:
                    results.append({"user_id": user_id, "status": "missing user data"})
                    continue
                
                # Check if the user already exists
                existing_user = users_collection.find_one({"user_id": user_id})
                if existing_user:
                    results.append({"user_id": user_id, "status": "already exists"})
                    continue

                # Add the new user (make sure to hash the password)
                new_user_data['user_id'] = user_id
                new_user_data['password'] = bcrypt.hashpw(new_user_data['password'].encode('utf-8'), bcrypt.gensalt())
                new_user_data['suspended'] = new_user_data.get('suspended', False)
                
                result = users_collection.insert_one(new_user_data)
                if result.inserted_id:
                    log_activity(user_id, "Bulk User Addition", "User added via bulk action.")
                    results.append({"user_id": user_id, "status": "added"})
                else:
                    results.append({"user_id": user_id, "status": "error adding user"})

        return jsonify({"results": results}), 200

    except Exception as e:
        app.logger.error(f"Error in bulk actions: {str(e)}")
        return jsonify({"error": "Internal Server Error"}), 500
    
@app.route('/admin/suspend_user', methods=['POST'])
@role_required('admin')
def suspend_user():
    user_data = request.json
    user_id = user_data.get('user_id')

    # Find the user in the database
    user = users_collection.find_one({"user_id": user_id})
    if not user:
        return jsonify({"error": f"User {user_id} not found."}), 404

    # Update the user's status to suspended
    result = users_collection.update_one({"user_id": user_id}, {"$set": {"suspended": True}})
    if result.matched_count == 0:
        return jsonify({"error": f"Failed to suspend user {user_id}."}), 500

    # Log user suspension activity
    log_activity(user_id, "Suspension", f"User {user_id} suspended.")

    return jsonify({"message": f"User {user_id} has been suspended."})


@app.route('/admin/unsuspend_user', methods=['POST'])
@role_required('admin')
def unsuspend_user():
    user_data = request.json
    user_id = user_data.get('user_id')

    # Find the user in the database
    user = users_collection.find_one({"user_id": user_id})
    if not user:
        return jsonify({"error": f"User {user_id} not found."}), 404

    # Update the user's status to unsuspended
    result = users_collection.update_one({"user_id": user_id}, {"$set": {"suspended": False}})
    if result.matched_count == 0:
        return jsonify({"error": f"Failed to unsuspend user {user_id}."}), 500

    # Log user unsuspension activity
    log_activity(user_id, "Unsuspension", f"User {user_id} unsuspended.")

    return jsonify({"message": f"User {user_id} has been unsuspended."})


# Performance check function (CPU usage)
def check_system_performance():
    cpu_usage = psutil.cpu_percent(interval=1)  # Get CPU usage percentage
    if cpu_usage > 80:  # Threshold set to 80% for alert
        send_real_time_alert(
            alert_type="System Performance Alert",
            message=f"High CPU usage detected: {cpu_usage}%",
            details="Consider optimizing the system or scaling resources."
        )

# Real-time data generation function
def generate_real_time_data():
    feature_names = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
        'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
        'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
        'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
    ]
    
    # Set the timezone to India Standard Time (IST)
    ist_tz = pytz.timezone('Asia/Kolkata')

    while True:
        # Create random data with feature names
        features = pd.DataFrame([np.random.rand(len(feature_names))], columns=feature_names)

        # Load model for prediction
        model = joblib.load(MODEL_PATH)
        label_mapping = {
            0: "DoS - back", 1: "U2R - buffer_overflow", 2: "R2L - ftp_write", 3: "R2L - guess_passwd",
            5: "Probe - ipsweep", 9: "DoS - neptune", 10: "Probe - nmap", 11: "Normal",
            15: "Probe - portsweep", 17: "Probe - satan", 18: "DoS - smurf", 21: "R2L - warezclient",
        }

        prediction_result = model.predict(features)[0]
        predicted_label = label_mapping.get(int(prediction_result), "Unknown")

        # Simulate client IP (for testing purposes)
        client_ip = "192.168.1.100"  # This should be the real client IP if available

        # Get current time in UTC and convert it to IST
        current_time_utc = datetime.datetime.now(pytz.utc)
        current_time_ist = current_time_utc.astimezone(ist_tz).strftime('%Y-%m-%d %I:%M:%S %p')

        data = {
            "timestamp": current_time_ist,  # Indian Standard Time
            "prediction": predicted_label,
            "confidence": 0.99,  # Mock confidence score
            "client_ip": client_ip  # Include client_ip in the emitted data
        }

        # Emit the data to the frontend in real-time
        socketio.emit('real-time-data', data)

        # Simulate intrusion detection (you can customize this for specific alert types)
        if predicted_label != "Normal":
            send_real_time_alert(
                alert_type="Intrusion Detected",
                message=f"Potential intrusion detected: {predicted_label}",
                details=f"Features: {features.to_dict()}"
            )

        # Perform system performance check periodically (e.g., every 10 iterations)
        if int(time.time()) % 10 == 0:
            check_system_performance()

        # Sleep for 1 second before generating the next data
        time.sleep(1)


@app.route('/login', methods=['POST'])
def login():
    user_id = request.json.get('user_id')
    password = request.json.get('password')
    
    logging.info(f"Login attempt for user: {user_id}")

    # Find the user in the database
    user = users_collection.find_one({"user_id": user_id})

    # If user is not found, return an error
    if not user:
        logging.error(f"User {user_id} not found.")
        return jsonify({"error": "User not found"}), 404

    # If password does not match, return an error
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        logging.error(f"Invalid password for user {user_id}.")
        return jsonify({"error": "Invalid password"}), 401

    # Check if the account is suspended
    if user.get("suspended"):
        logging.warning(f"User {user_id} is suspended.")
        return jsonify({"error": "Your account has been suspended."}), 403

    # Fetch the role from the user document
    role = user.get('role', 'user')  # Default to 'user' if no role is found

    # Generate JWT token upon successful login
    token = generate_jwt(user_id, role)

    # Log the login attempt with additional details
    log_entry = {
        "user_id": user_id,
        "timestamp": datetime.datetime.now(pytz.utc).astimezone(pytz.timezone('Asia/Kolkata')).strftime('%Y-%m-%d %I:%M:%S %p'),
        "client_ip": request.remote_addr,  # Capturing the client IP address
        "user_agent": request.headers.get('User-Agent')  # Capturing the user agent (browser info)
    }

    # Insert the login attempt log into MongoDB
    db.user_login_history.insert_one(log_entry)

    # Log successful login for audit
    log_activity(user_id, "Login", "User successfully logged in.")

    # Return the token and role in the response
    return jsonify({"token": token, "role": role}), 200



@app.route('/predict', methods=['POST'])
@role_required('user')
def predict():
    try:
        client_ip = request.remote_addr  # This will give you the IP address of the client

        encrypted_data = request.json.get('encrypted_features')
        
        if not encrypted_data:
            logging.error("Encrypted features missing")
            return jsonify({"error": "Missing encrypted features."}), 400

        # Deserialize the encrypted features JSON
        encrypted_features = json.loads(encrypted_data)
        encrypted_aes_key = encrypted_features.get('aes_key')
        nonce = encrypted_features.get('nonce')
        ciphertext = encrypted_features.get('ciphertext')
        tag = encrypted_features.get('tag')

        # Log the received encrypted data
        logging.debug(f"Encrypted AES key: {encrypted_aes_key}")
        logging.debug(f"Nonce: {nonce}")
        logging.debug(f"Ciphertext: {ciphertext}")
        logging.debug(f"Tag: {tag}")
        
        # Decrypt the AES key
        private_key = load_private_key()
        aes_key = decrypt_aes_key(private_key, encrypted_aes_key)
        
        # Decrypt the features using the AES key
        decrypted_features = decrypt_features(aes_key, nonce, ciphertext, tag)

        # Ensure the feature names match the ones used during training
        feature_names = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
            'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]

        # Update the feature names in the decrypted features
        decrypted_features.columns = feature_names  # Align columns with training feature names

        # Log the decrypted features for debugging
        logging.debug(f"Decrypted features columns: {decrypted_features.columns}")

        # Ensure the features are in 2D array format for prediction
        # If the decrypted features are 1D, expand it to 2D (e.g., (1, n_features))
        if decrypted_features.ndim == 1:
            decrypted_features = np.expand_dims(decrypted_features, axis=0)

        # If decrypted_features is still more than 2D, reshape it properly to 2D
        if decrypted_features.ndim > 2:
            decrypted_features = decrypted_features.reshape(1, -1)  # Reshape to 2D

        # Make the prediction
        prediction_result = model.predict(decrypted_features)[0]
        predicted_label = label_mapping.get(int(prediction_result), "Unknown")
        
        return jsonify({"prediction": predicted_label,
                        "client_ip": client_ip})
    
    except Exception as e:
        logging.error(f"Prediction error: {e}")
        return jsonify({"error": "Prediction failed."}), 500


@app.route('/user-info', methods=['GET'])
@role_required('user')
def get_user_info():
    token = request.headers.get('Authorization', '').split(" ")[1]
    decoded = verify_jwt(token)
    if not decoded:
        return jsonify({"error": "Invalid token."}), 403

    user_id = decoded.get('user_id')
    user = users_collection.find_one({"user_id": user_id}, {"_id": 0, "password": 0})

    if not user:
        return jsonify({"error": "User not found."}), 404

    return jsonify({"user_info": user})

# Endpoint for updating user password
@app.route('/update-password', methods=['POST'])
@role_required('user')
def update_password():
    user_data = request.json
    old_password = user_data.get('old_password')
    new_password = user_data.get('new_password')

    token = request.headers.get('Authorization', '').split(" ")[1]
    decoded = verify_jwt(token)
    if not decoded:
        return jsonify({"error": "Invalid token."}), 403

    user_id = decoded.get('user_id')
    
    # Use find_one to get the user based on user_id
    user = users_collection.find_one({"user_id": user_id})

    if not user:
        return jsonify({"error": "User not found."}), 404

    # Check the old password
    if not bcrypt.checkpw(old_password.encode('utf-8'), user['password']):
        return jsonify({"error": "Incorrect old password"}), 401

    # Update the password
    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    result = users_collection.update_one(
        {"user_id": user_id},
        {"$set": {"password": hashed_new_password}}
    )

    if result.modified_count == 0:
        return jsonify({"error": "Password update failed."}), 500

    return jsonify({"message": "Password updated successfully"}), 200

if __name__ == "__main__":
    # Thread(target=generate_real_time_data, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5000)
