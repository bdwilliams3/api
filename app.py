from flask import Flask, jsonify, request, make_response
import json
import jwt
import hashlib
import hmac
import base64
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Self-contained secrets - varied formats for authenticity
SECRETS = {
    'api_key': f"sk_live_{secrets.token_hex(20)}",  # Stripe-style key
    'basic_user': 'challenger',
    'basic_pass': base64.b64encode(f"pass_{datetime.now().strftime('%Y%m%d')}".encode()).decode()[:16],
    'bearer_secret': secrets.token_urlsafe(43),  # URL-safe base64, standard length
    'jwt_secret': hashlib.sha256(f"jwt_{datetime.now().isoformat()}".encode()).hexdigest(),
    'hmac_secret': base64.b64encode(secrets.token_bytes(32)).decode(),
    'signature_key': secrets.token_hex(24) 
}

# Active bearer tokens (in-memory store)
active_tokens = {}

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Health check
@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    return jsonify({"status": "healthy"}), 200

# Game start
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        "game": "Authentication Gauntlet",
        "tagline": "Master 10 authentication methods to reach the summit",
        "start": "GET /api/level/1",
        "warning": "Each level's response contains the key to the next. Read carefully."
    }), 200

# LEVEL 1: No Authentication
@app.route('/api/level/1', methods=['GET'])
def level1():
    response = make_response(jsonify({
        "level": 1,
        "name": "Open Gate",
        "status": "conquered",
        "flag": "FLAG{w3lc0m3_t0_th3_g4untl3t}",
        "message": "Welcome, seeker. No locks bar this door.",
        "wisdom": "Not all treasures require keys, but the path ahead grows darker."
    }))
    
    # Hidden hint in custom header
    response.headers['X-Next-Challenge'] = 'Level 2 seeks a key. Look for X-API-Key header.'
    response.headers['X-Hint'] = f"The key you seek: {SECRETS['api_key']}"
    
    return response, 200

# LEVEL 2: Plain Header API Key
@app.route('/api/level/2', methods=['GET'])
def level2():
    api_key = request.headers.get('X-API-Key')
    
    if not api_key:
        return jsonify({
            "level": 2,
            "name": "Simple Lock",
            "status": "locked",
            "error": "Missing key. Check your headers.",
            "hint": "Look at the previous level's response headers carefully."
        }), 401
    
    if api_key != SECRETS['api_key']:
        return jsonify({
            "level": 2,
            "status": "locked",
            "error": "Wrong key. The gate remains shut."
        }), 403
    
    response = make_response(jsonify({
        "level": 2,
        "name": "Simple Lock",
        "status": "conquered",
        "flag": "FLAG{pl41n_k3y_m4st3r}",
        "message": "A simple key opens a simple lock.",
        "wisdom": "But what if the key itself could speak your name?"
    }))
    
    # Encode credentials for next level
    creds = f"{SECRETS['basic_user']}:{SECRETS['basic_pass']}"
    encoded = base64.b64encode(creds.encode()).decode()
    
    response.headers['X-Next-Challenge'] = 'Level 3 requires Basic Authentication'
    response.headers['X-Hint'] = f"Authorization: Basic {encoded}"
    response.headers['X-Cipher'] = 'Base64 encoding hides but does not protect'
    
    return response, 200

# LEVEL 3: Basic Authentication
@app.route('/api/level/3', methods=['GET'])
def level3():
    auth = request.authorization
    
    if not auth:
        response = make_response(jsonify({
            "level": 3,
            "name": "Named Guardian",
            "status": "locked",
            "error": "Who goes there? Speak your name and password.",
            "hint": "Authorization: Basic <base64(username:password)>"
        }))
        response.headers['WWW-Authenticate'] = 'Basic realm="Level 3"'
        return response, 401
    
    if auth.username != SECRETS['basic_user'] or auth.password != SECRETS['basic_pass']:
        return jsonify({
            "level": 3,
            "status": "locked",
            "error": "False identity rejected."
        }), 403
    
    # Generate bearer token for next level
    token = secrets.token_urlsafe(32)
    active_tokens[token] = {
        'created': datetime.utcnow(),
        'user': auth.username
    }
    
    response = make_response(jsonify({
        "level": 3,
        "name": "Named Guardian",
        "status": "conquered",
        "flag": "FLAG{b4s1c_but_us3ful}",
        "message": "Your identity is confirmed.",
        "wisdom": "Static names grow stale. What if your identity could expire?"
    }))
    
    response.headers['X-Next-Challenge'] = 'Level 4 requires a Bearer token'
    response.headers['X-Bearer-Token'] = token
    response.headers['X-Token-Expires'] = '5 minutes'
    
    return response, 200

# LEVEL 4: Bearer Token
@app.route('/api/level/4', methods=['GET'])
def level4():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "level": 4,
            "name": "Time-Bound Seal",
            "status": "locked",
            "error": "Bearer token required",
            "hint": "Authorization: Bearer <token>"
        }), 401
    
    token = auth_header.split(' ')[1]
    
    if token not in active_tokens:
        return jsonify({
            "level": 4,
            "status": "locked",
            "error": "Invalid or expired token"
        }), 403
    
    # Check token age
    token_data = active_tokens[token]
    age = (datetime.utcnow() - token_data['created']).total_seconds()
    if age > 300:  # 5 minutes
        del active_tokens[token]
        return jsonify({
            "level": 4,
            "status": "locked",
            "error": "Token expired"
        }), 401
    
    response = make_response(jsonify({
        "level": 4,
        "name": "Time-Bound Seal",
        "status": "conquered",
        "flag": "FLAG{b34r3r_0f_t1m3}",
        "message": "The temporal seal recognizes your token.",
        "wisdom": "Time flows, but what if each moment required its own proof?"
    }))
    
    # Provide signature components for next level
    timestamp = str(int(datetime.utcnow().timestamp()))
    method = "GET"
    path = "/api/level/5"
    message = f"{method}|{path}|{timestamp}"
    signature = hmac.new(
        SECRETS['signature_key'].encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    response.headers['X-Next-Challenge'] = 'Level 5 requires request signing with timestamp'
    response.headers['X-Signature-Key'] = SECRETS['signature_key']
    response.headers['X-Signature-Format'] = 'HMAC-SHA256(method|path|timestamp)'
    response.headers['X-Example-Timestamp'] = timestamp
    response.headers['X-Example-Signature'] = signature
    
    return response, 200

# LEVEL 5: API Signature with Timestamp
@app.route('/api/level/5', methods=['GET'])
def level5():
    timestamp = request.headers.get('X-Timestamp')
    signature = request.headers.get('X-Signature')
    
    if not timestamp or not signature:
        return jsonify({
            "level": 5,
            "name": "Temporal Cipher",
            "status": "locked",
            "error": "Missing X-Timestamp or X-Signature",
            "hint": "Sign your request: HMAC-SHA256(method|path|timestamp)"
        }), 401
    
    # Verify timestamp (within 2 minutes)
    try:
        ts = int(timestamp)
        now = int(datetime.utcnow().timestamp())
        if abs(now - ts) > 120:
            return jsonify({
                "level": 5,
                "status": "locked",
                "error": "Timestamp too old or future. Must be within 2 minutes."
            }), 401
    except ValueError:
        return jsonify({
            "level": 5,
            "status": "locked",
            "error": "Invalid timestamp format"
        }), 400
    
    # Verify signature
    message = f"GET|/api/level/5|{timestamp}"
    expected = hmac.new(
        SECRETS['signature_key'].encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    if signature != expected:
        return jsonify({
            "level": 5,
            "status": "locked",
            "error": "Invalid signature",
            "debug": f"Expected format: HMAC-SHA256('{message}')"
        }), 403
    
    response = make_response(jsonify({
        "level": 5,
        "name": "Temporal Cipher",
        "status": "conquered",
        "flag": "FLAG{s1gn3d_4nd_d4t3d}",
        "message": "Your signature proves both identity and timeliness.",
        "wisdom": "But signatures can be forged. What if the message carried its own truth?"
    }))
    
    # Generate JWT for next level
    payload = {
        'sub': 'challenger',
        'level': 6,
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, SECRETS['jwt_secret'], algorithm='HS256')
    
    response.headers['X-Next-Challenge'] = 'Level 6 requires a JWT token'
    response.headers['X-JWT-Token'] = token
    response.headers['X-JWT-Secret'] = SECRETS['jwt_secret']
    response.headers['X-Algorithm'] = 'HS256'
    
    return response, 200

# LEVEL 6: JWT Tokens
@app.route('/api/level/6', methods=['GET'])
def level6():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "level": 6,
            "name": "Self-Signed Scroll",
            "status": "locked",
            "error": "JWT Bearer token required",
            "hint": "Authorization: Bearer <jwt-token>"
        }), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        payload = jwt.decode(token, SECRETS['jwt_secret'], algorithms=['HS256'])
        
        if payload.get('level') != 6:
            return jsonify({
                "level": 6,
                "status": "locked",
                "error": "Token not issued for this level"
            }), 403
            
    except jwt.ExpiredSignatureError:
        return jsonify({
            "level": 6,
            "status": "locked",
            "error": "JWT expired"
        }), 401
    except jwt.InvalidTokenError as e:
        return jsonify({
            "level": 6,
            "status": "locked",
            "error": f"Invalid JWT: {str(e)}"
        }), 401
    
    response = make_response(jsonify({
        "level": 6,
        "name": "Self-Signed Scroll",
        "status": "conquered",
        "flag": "FLAG{jwt_w1z4rd}",
        "message": "The scroll bears its own seal of authenticity.",
        "wisdom": "Signatures within messages—elegant. But what of shared secrets?"
    }))
    
    response.headers['X-Next-Challenge'] = 'Level 7 requires HMAC signing with shared secret'
    response.headers['X-HMAC-Secret'] = SECRETS['hmac_secret']
    response.headers['X-HMAC-Format'] = 'HMAC-SHA256(secret + body_content)'
    response.headers['X-Method'] = 'POST with JSON body'
    
    return response, 200

# LEVEL 7: HMAC Signing
@app.route('/api/level/7', methods=['POST'])
def level7():
    hmac_sig = request.headers.get('X-HMAC-Signature')
    
    if not hmac_sig:
        return jsonify({
            "level": 7,
            "name": "Shared Secret Ritual",
            "status": "locked",
            "error": "Missing X-HMAC-Signature header",
            "hint": "POST with JSON body, sign with HMAC-SHA256(secret + body)"
        }), 401
    
    # Get request body
    try:
        body = request.get_data(as_text=True)
        if not body:
            return jsonify({
                "level": 7,
                "status": "locked",
                "error": "Request body required"
            }), 400
    except:
        return jsonify({
            "level": 7,
            "status": "locked",
            "error": "Invalid request body"
        }), 400
    
    # Calculate expected HMAC
    message = SECRETS['hmac_secret'] + body
    expected = hmac.new(
        message.encode(),
        digestmod=hashlib.sha256
    ).hexdigest()
    
    if hmac_sig != expected:
        return jsonify({
            "level": 7,
            "status": "locked",
            "error": "Invalid HMAC signature",
            "hint": "HMAC-SHA256(secret + request_body)"
        }), 403
    
    response = make_response(jsonify({
        "level": 7,
        "name": "Shared Secret Ritual",
        "status": "conquered",
        "flag": "FLAG{hm4c_m4st3r_c1ph3r}",
        "message": "The shared secret proves our bond.",
        "wisdom": "Trust through shared knowledge. But what if we needed no shared secrets at all?"
    }))
    
    response.headers['X-Next-Challenge'] = 'Level 8 requires Mutual TLS (mTLS)'
    response.headers['X-Warning'] = 'Client certificates required - prepare your TLS handshake'
    response.headers['X-Note'] = 'In production, nginx handles mTLS. For this game, use X-Client-Cert header with cert fingerprint'
    response.headers['X-Valid-Fingerprint'] = hashlib.sha256(b'challenge-client-cert').hexdigest()
    
    return response, 200

# LEVEL 8: Mutual TLS (Simulated)
@app.route('/api/level/8', methods=['GET'])
def level8():
    # In real mTLS, nginx/reverse proxy handles this
    # For the game, we simulate with a cert fingerprint header
    client_cert = request.headers.get('X-Client-Cert-Fingerprint')
    
    if not client_cert:
        return jsonify({
            "level": 8,
            "name": "Two-Way Trust",
            "status": "locked",
            "error": "Client certificate required",
            "hint": "X-Client-Cert-Fingerprint header needed",
            "note": "Simulate cert with SHA256 fingerprint"
        }), 401
    
    # Verify cert fingerprint
    expected_fingerprint = hashlib.sha256(b'challenge-client-cert').hexdigest()
    
    if client_cert != expected_fingerprint:
        return jsonify({
            "level": 8,
            "status": "locked",
            "error": "Invalid client certificate"
        }), 403
    
    response = make_response(jsonify({
        "level": 8,
        "name": "Two-Way Trust",
        "status": "conquered",
        "flag": "FLAG{mutual_tls_h4ndsh4k3}",
        "message": "Both parties present their seals. Trust is mutual.",
        "wisdom": "Beyond HTTP lies the realm of enterprise. Can you speak the ancient tongue of SAML?"
    }))
    
    # SAML is complex - provide simplified assertion
    saml_assertion = base64.b64encode(f'''
    <saml:Assertion>
        <saml:Subject>
            <saml:NameID>challenger@gauntlet.local</saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="{datetime.utcnow().isoformat()}" />
        <saml:AuthnStatement>
            <saml:AuthnContext>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContext>
        </saml:AuthnStatement>
        <Signature>{hashlib.sha256(b"saml-signature-secret").hexdigest()}</Signature>
    </saml:Assertion>
    '''.encode()).decode()
    
    response.headers['X-Next-Challenge'] = 'Level 9 requires SAML assertion'
    response.headers['X-SAML-Assertion'] = saml_assertion
    response.headers['X-SAML-Format'] = 'Base64-encoded XML assertion in X-SAML-Token header'
    
    return response, 200

# LEVEL 9: SAML Federation (Simplified)
@app.route('/api/level/9', methods=['POST'])
def level9():
    saml_token = request.headers.get('X-SAML-Token')
    
    if not saml_token:
        return jsonify({
            "level": 9,
            "name": "Federation Gateway",
            "status": "locked",
            "error": "SAML assertion required",
            "hint": "POST with X-SAML-Token header containing base64-encoded SAML"
        }), 401
    
    try:
        # Decode SAML
        decoded = base64.b64decode(saml_token).decode()
        
        # Simple validation - check for required elements
        required = ['<saml:Assertion>', '<saml:Subject>', '<Signature>']
        if not all(elem in decoded for elem in required):
            return jsonify({
                "level": 9,
                "status": "locked",
                "error": "Invalid SAML assertion - missing required elements"
            }), 403
        
        # Check signature
        sig_hash = hashlib.sha256(b"saml-signature-secret").hexdigest()
        if sig_hash not in decoded:
            return jsonify({
                "level": 9,
                "status": "locked",
                "error": "Invalid SAML signature"
            }), 403
            
    except Exception as e:
        return jsonify({
            "level": 9,
            "status": "locked",
            "error": f"Failed to parse SAML: {str(e)}"
        }), 400
    
    response = make_response(jsonify({
        "level": 9,
        "name": "Federation Gateway",
        "status": "conquered",
        "flag": "FLAG{s4ml_f3d3r4t10n_m4st3r}",
        "message": "Enterprise gates open. The old protocols still hold power.",
        "wisdom": "But the future approaches. Quantum storms gather on the horizon..."
    }))
    
    response.headers['X-Next-Challenge'] = 'Level 10 - The Final Trial'
    response.headers['X-Final-Boss'] = 'OAuth 2.0 with PKCE flow'
    response.headers['X-OAuth-Client-ID'] = 'gauntlet_challenger'
    response.headers['X-OAuth-Challenge-Method'] = 'S256'
    
    # Generate code verifier and challenge for PKCE
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    
    response.headers['X-Code-Verifier'] = code_verifier
    response.headers['X-Code-Challenge'] = code_challenge
    response.headers['X-Auth-Endpoint'] = '/api/level/10/authorize'
    response.headers['X-Token-Endpoint'] = '/api/level/10/token'
    
    return response, 200

# LEVEL 10: OAuth 2.0 with PKCE
# Step 1: Authorization request
@app.route('/api/level/10/authorize', methods=['GET'])
def level10_authorize():
    client_id = request.args.get('client_id')
    code_challenge = request.args.get('code_challenge')
    code_challenge_method = request.args.get('code_challenge_method')
    redirect_uri = request.args.get('redirect_uri', '/api/level/10/callback')
    
    if not all([client_id, code_challenge, code_challenge_method]):
        return jsonify({
            "error": "invalid_request",
            "error_description": "Missing required parameters: client_id, code_challenge, code_challenge_method"
        }), 400
    
    if client_id != 'gauntlet_challenger':
        return jsonify({
            "error": "invalid_client",
            "error_description": "Unknown client_id"
        }), 401
    
    if code_challenge_method != 'S256':
        return jsonify({
            "error": "invalid_request",
            "error_description": "Only S256 challenge method supported"
        }), 400
    
    # Generate authorization code
    auth_code = secrets.token_urlsafe(32)
    
    # Store code challenge for verification
    active_tokens[auth_code] = {
        'code_challenge': code_challenge,
        'created': datetime.utcnow()
    }
    
    return jsonify({
        "authorization_code": auth_code,
        "expires_in": 300,
        "next_step": f"POST {redirect_uri}?code={auth_code} with code_verifier"
    }), 200

# Step 2: Token exchange
@app.route('/api/level/10/token', methods=['POST'])
def level10_token():
    data = request.get_json() or {}
    
    grant_type = data.get('grant_type')
    code = data.get('code')
    code_verifier = data.get('code_verifier')
    client_id = data.get('client_id')
    
    if grant_type != 'authorization_code':
        return jsonify({
            "error": "unsupported_grant_type"
        }), 400
    
    if not all([code, code_verifier, client_id]):
        return jsonify({
            "error": "invalid_request",
            "error_description": "Missing required parameters"
        }), 400
    
    if code not in active_tokens:
        return jsonify({
            "error": "invalid_grant",
            "error_description": "Invalid or expired authorization code"
        }), 401
    
    # Verify PKCE
    stored_challenge = active_tokens[code]['code_challenge']
    computed_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip('=')
    
    if stored_challenge != computed_challenge:
        return jsonify({
            "error": "invalid_grant",
            "error_description": "Code verifier does not match challenge"
        }), 401
    
    # Generate access token
    access_token = jwt.encode({
        'sub': client_id,
        'scope': 'final_level',
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }, SECRETS['jwt_secret'], algorithm='HS256')
    
    # Clean up auth code
    del active_tokens[code]
    
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "final_level",
        "next_step": "GET /api/level/10 with Bearer token"
    }), 200

# Step 3: Protected resource
@app.route('/api/level/10', methods=['GET'])
def level10():
    auth_header = request.headers.get('Authorization')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            "level": 10,
            "name": "OAuth Summit",
            "status": "locked",
            "error": "OAuth 2.0 access token required",
            "flow": "1. GET /api/level/10/authorize with PKCE params",
            "flow_2": "2. POST /api/level/10/token to exchange code",
            "flow_3": "3. GET /api/level/10 with access token"
        }), 401
    
    token = auth_header.split(' ')[1]
    
    try:
        payload = jwt.decode(token, SECRETS['jwt_secret'], algorithms=['HS256'])
        
        if payload.get('scope') != 'final_level':
            return jsonify({
                "level": 10,
                "status": "locked",
                "error": "Insufficient scope"
            }), 403
            
    except jwt.ExpiredSignatureError:
        return jsonify({
            "level": 10,
            "status": "locked",
            "error": "Access token expired"
        }), 401
    except jwt.InvalidTokenError:
        return jsonify({
            "level": 10,
            "status": "locked",
            "error": "Invalid access token"
        }), 401
    
    return jsonify({
        "level": 10,
        "name": "OAuth Summit",
        "status": "CONQUERED",
        "flag": "FLAG{04uth_pk c3_l3g3nd}",
        "message": "YOU HAVE REACHED THE SUMMIT",
        "achievement": "Master of All Authentication",
        "conquered_levels": [
            "No Auth", "Plain Header", "Basic Auth", 
            "Bearer Token", "API Signature", "JWT",
            "HMAC Signing", "Mutual TLS", "SAML Federation",
            "OAuth 2.0 with PKCE"
        ],
        "final_wisdom": "From open gates to cryptographic peaks, you have mastered the gauntlet. The APIs bow to your knowledge."
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)