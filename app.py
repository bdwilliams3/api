from flask import Flask, jsonify, request
import json
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os
import hvac
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid

app = Flask(__name__)

# Vault Configuration
VAULT_ADDR = os.getenv('VAULT_ADDR', 'http://vault.vault.svc.cluster.local:8200')
VAULT_ROLE = os.getenv('VAULT_ROLE', 'api-role')
K8S_SA_TOKEN_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/token'

# JWT Configuration
JWT_ALGORITHM = 'HS256'
JWT_EXP_HOURS = 1  # JWT expires in 1 hour
GUEST_JWT_EXP_HOURS = 24  # Guest JWT expires in 24 hours

# Initialize Vault client
vault_client = None
jwt_secret = None
clients_cache = {}
cache_timestamp = None
CACHE_TTL = 300  # 5 minutes

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# Initialize Vault connection
def init_vault():
    global vault_client, jwt_secret
    try:
        # Read Kubernetes service account token
        with open(K8S_SA_TOKEN_PATH, 'r') as f:
            k8s_token = f.read().strip()
        
        # Create Vault client
        client = hvac.Client(url=VAULT_ADDR)
        
        # Authenticate with Kubernetes auth method
        auth_response = client.auth.kubernetes.login(
            role=VAULT_ROLE,
            jwt=k8s_token
        )
        
        vault_client = client
        
        # Read JWT secret from Vault
        jwt_secret_data = vault_client.secrets.kv.v2.read_secret_version(
            path='jwt-config',
            mount_point='secret'
        )
        jwt_secret = jwt_secret_data['data']['data']['secret']
        
        app.logger.info("Successfully connected to Vault")
        return True
        
    except Exception as e:
        app.logger.error(f"Failed to connect to Vault: {e}")
        return False

# Load clients from Vault with caching
def load_clients():
    global clients_cache, cache_timestamp
    
    # Check cache
    if cache_timestamp and (datetime.utcnow() - cache_timestamp).total_seconds() < CACHE_TTL:
        return clients_cache
    
    try:
        # List all client secrets
        client_list = vault_client.secrets.kv.v2.list_secrets(
            path='clients',
            mount_point='secret'
        )
        
        clients = {}
        for client_key in client_list['data']['keys']:
            client_data = vault_client.secrets.kv.v2.read_secret_version(
                path=f'clients/{client_key}',
                mount_point='secret'
            )
            data = client_data['data']['data']
            clients[data['client_id']] = data['client_secret']
        
        clients_cache = clients
        cache_timestamp = datetime.utcnow()
        return clients
        
    except Exception as e:
        app.logger.error(f"Failed to load clients from Vault: {e}")
        return clients_cache  # Return cached data if available

# Health check endpoint (no auth required)
@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    vault_status = "ready" if vault_client and vault_client.is_authenticated() else "sealed"
    return jsonify({
        "status": "healthy",
        "vault": vault_status
    }), 200

# Generate JWT token
def generate_jwt(client_id, is_guest=False):
    exp_hours = GUEST_JWT_EXP_HOURS if is_guest else JWT_EXP_HOURS
    payload = {
        'client_id': client_id,
        'is_guest': is_guest,
        'exp': datetime.utcnow() + timedelta(hours=exp_hours),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, jwt_secret, algorithm=JWT_ALGORITHM)

# Decode JWT token
def decode_jwt(token):
    try:
        payload = jwt.decode(token, jwt_secret, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

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
                return jsonify({"error": "Invalid authentication scheme. Use 'Bearer <token>'"}), 401
            
            # Decode and validate JWT
            payload = decode_jwt(token)
            if not payload:
                return jsonify({"error": "Invalid or expired token"}), 401
            
            # Add client info to request context
            request.client_id = payload['client_id']
            request.is_guest = payload.get('is_guest', False)
            
        except ValueError:
            return jsonify({"error": "Invalid Authorization header format"}), 401
        except Exception as e:
            return jsonify({"error": "Authentication failed"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# TOKEN ENDPOINT - Exchange client_id/client_secret for JWT
@app.route('/api/token', methods=['POST'])
@limiter.limit("10 per minute")
def get_token():
    credentials = request.json
    client_id = credentials.get('client_id')
    client_secret = credentials.get('client_secret')
    
    if not client_id or not client_secret:
        return jsonify({"error": "client_id and client_secret required"}), 400
    
    # Validate client credentials from Vault
    clients = load_clients()
    
    if client_id not in clients or clients[client_id] != client_secret:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Generate JWT
    token = generate_jwt(client_id)
    
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": JWT_EXP_HOURS * 3600  # seconds
    }), 200

# GUEST TOKEN ENDPOINT - Generate JWT for guest users
@app.route('/api/token/guest', methods=['POST'])
@limiter.limit("20 per hour")
def get_guest_token():
    # Generate a unique guest ID
    guest_id = f"guest_{uuid.uuid4().hex[:12]}"
    
    # Generate JWT with guest flag
    token = generate_jwt(guest_id, is_guest=True)
    
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": GUEST_JWT_EXP_HOURS * 3600,  # seconds
        "guest_id": guest_id,
        "message": "Guest token generated successfully"
    }), 200

# Data endpoints
def load_data():
    with open('data.json') as json_file:
        return json.load(json_file)

def save_data(data):
    with open('data.json', 'w') as json_file:
        json.dump(data, json_file, indent=2)

@app.route('/api/data', methods=['GET'])
@require_auth
def get_data():
    data = load_data()
    # Optionally, you can add guest-specific logic here
    # For example, filter or limit data for guest users
    if hasattr(request, 'is_guest') and request.is_guest:
        app.logger.info(f"Guest user {request.client_id} accessed data")
    return jsonify(data)

@app.route('/api/data', methods=['POST'])
@require_auth
def add_data():
    # Optional: Restrict certain operations for guest users
    if hasattr(request, 'is_guest') and request.is_guest:
        return jsonify({"error": "Guest users cannot add data"}), 403
    
    new_entry = request.json
    data = load_data()
    data.append(new_entry)
    save_data(data)
    return jsonify(new_entry), 201

@app.route('/api/data/<int:item_id>', methods=['PUT'])
@require_auth
def update_data(item_id):
    # Optional: Restrict certain operations for guest users
    if hasattr(request, 'is_guest') and request.is_guest:
        return jsonify({"error": "Guest users cannot update data"}), 403
    
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
    # Optional: Restrict certain operations for guest users
    if hasattr(request, 'is_guest') and request.is_guest:
        return jsonify({"error": "Guest users cannot delete data"}), 403
    
    data = load_data()

    if item_id < 0 or item_id >= len(data):
        return jsonify({"error": "Item not found"}), 404

    deleted_entry = data.pop(item_id)
    save_data(data)
    return jsonify(deleted_entry), 200

if __name__ == '__main__':
    # Initialize Vault connection on startup
    if not init_vault():
        app.logger.error("Failed to initialize Vault connection")
        exit(1)
    
    app.run(host='0.0.0.0', port=8080)