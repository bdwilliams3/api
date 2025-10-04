from flask import Flask, jsonify, request
import json
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# Load users database
def load_users():
    try:
        with open('users.json') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"users": []}

def save_users(users_data):
    with open('users.json', 'w') as f:
        json.dump(users_data, f, indent=2)

# Load active tokens (in production, use Redis or a proper database)
def load_tokens():
    try:
        with open('tokens.json') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_tokens(tokens):
    with open('tokens.json', 'w') as f:
        json.dump(tokens, f, indent=2)

# Hash password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({"error": "Authorization header missing"}), 401
        
        try:
            scheme, token = auth_header.split()
            if scheme.lower() != 'bearer':
                return jsonify({"error": "Invalid authentication scheme"}), 401
            
            # Validate token
            tokens = load_tokens()
            if token not in tokens:
                return jsonify({"error": "Invalid or expired token"}), 403
            
            # Check token expiration (optional)
            token_data = tokens[token]
            expiry = datetime.fromisoformat(token_data['expires'])
            if datetime.now() > expiry:
                return jsonify({"error": "Token expired"}), 403
            
            # Add user info to request context
            request.current_user = token_data['username']
            
        except ValueError:
            return jsonify({"error": "Invalid Authorization header format"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# LOGIN ENDPOINT
@app.route('/api/login', methods=['POST'])
def login():
    credentials = request.json
    username = credentials.get('username')
    password = credentials.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    # Validate credentials
    users_data = load_users()
    user = next((u for u in users_data['users'] if u['username'] == username), None)
    
    if not user or user['password'] != hash_password(password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Generate token
    token = secrets.token_urlsafe(32)
    
    # Store token with expiration (24 hours)
    tokens = load_tokens()
    tokens[token] = {
        "username": username,
        "created": datetime.now().isoformat(),
        "expires": (datetime.now() + timedelta(hours=24)).isoformat()
    }
    save_tokens(tokens)
    
    return jsonify({
        "token": token,
        "expires_in": 86400  # 24 hours in seconds
    }), 200

# LOGOUT ENDPOINT
@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    auth_header = request.headers.get('Authorization')
    token = auth_header.split()[1]
    
    tokens = load_tokens()
    if token in tokens:
        del tokens[token]
        save_tokens(tokens)
    
    return jsonify({"message": "Logged out successfully"}), 200

# REGISTER ENDPOINT (optional)
@app.route('/api/register', methods=['POST'])
def register():
    user_data = request.json
    username = user_data.get('username')
    password = user_data.get('password')
    
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    
    users_data = load_users()
    
    # Check if user exists
    if any(u['username'] == username for u in users_data['users']):
        return jsonify({"error": "Username already exists"}), 409
    
    # Add new user
    users_data['users'].append({
        "username": username,
        "password": hash_password(password)
    })
    save_users(users_data)
    
    return jsonify({"message": "User registered successfully"}), 201

# Your existing data endpoints
def load_data():
    with open('data.json') as json_file:
        return json.load(json_file)

def save_data(data):
    with open('data.json', 'w') as json_file:
        json.dump(data, json_file)

@app.route('/api/data', methods=['GET'])
@require_auth
def get_data():
    data = load_data()
    return jsonify(data)

@app.route('/api/data', methods=['POST'])
@require_auth
def add_data():
    new_entry = request.json
    data = load_data()
    data.append(new_entry)
    save_data(data)
    return jsonify(new_entry), 201

@app.route('/api/data/<int:item_id>', methods=['PUT'])
@require_auth
def update_data(item_id):
    updated_entry = request.json
    data = load_data()

    if item_id < 0 or item_id >= len(data):
        return jsonify({"error": "Item not found"}), 404

    data[item_id] = updated_entry
    save_data(data)
    return jsonify(updated_entry)

@app.route('/api/data/<int:item_id>', methods=['DELETE'])
@require_auth
def delete_data(item_id):
    data = load_data()

    if item_id < 0 or item_id >= len(data):
        return jsonify({"error": "Item not found"}), 404

    deleted_entry = data.pop(item_id)
    save_data(data)
    return jsonify(deleted_entry), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
