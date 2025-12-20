import hashlib
import secrets
import jwt
import hmac
import time
from flask import Flask, jsonify, request, make_response
from datetime import datetime, timedelta
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# SECURITY: High-entropy seed in RAM. No K8s connection.
INTERNAL_SEED = secrets.token_hex(64)
def derive_key(purpose):
    return hashlib.sha256(f"{INTERNAL_SEED}-{purpose}".encode()).hexdigest()

JWT_SECRET = derive_key("jwt-signing")
fail_tracker = {}

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri="memory://"
)

def get_terminal_banner(level_num, custom_text):
    border = "-" * 150
    return f"{border}\nLevel {level_num}\n{border}\n{' ' * 26}< {custom_text:^90} >\n{border}\n"

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Request-ID'] = secrets.token_hex(8)
    response.headers['X-Gateway-Instance'] = 'node-af72'
    response.headers.pop('Server', None)
    return response

# ==========================================
# Public Access Levels
# ==========================================
@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "UP"}), 200

@app.route('/api', methods=['GET'])
def level_0():
    res = make_response(jsonify({
        "message": "Welcome to the api Authentication Game.",
        "username": "api_hunter",
        "next_level": "https://sample-api.com/api/level/1",
    }))
    res.headers['X-Secret'] = 'p@s5W0rD'
    return res, 200

# ==========================================
# LEVEL 1: PROGRESSIVE BASIC AUTH
# ==========================================
@app.route('/api/level/1', methods=['GET'])
def level_1():
    ip = get_remote_address()
    auth = request.authorization

    if auth and auth.username == "api_hunter" and auth.password == "p@s5W0rD":
        fail_tracker.pop(ip, None)
        msg = get_terminal_banner(1, "You have successfully authenticated via basic auth. Keep checking headers for hints.")
        res = make_response(jsonify(
            {
                "level": 1, 
                "status": "passed", 
                "message": msg, 
                "next_level": "https://sample-api.com/api/level/1"
                }
            )
        )
        return res

    fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
    count = fail_tracker[ip]
    hints = {
        1: "Check the response headers. Look for 'WWW-Authenticate'.",
        2: "The 'Basic' scheme is being requested.",
        3: "Basic Auth needs 'username' (from Level 0) and the password 'password'."
    }
    res = make_response(jsonify({"level": 1, "hint": hints.get(count, [3])}), 401)
    res.headers['WWW-Authenticate'] = 'Basic realm="Level 1"'
    return res

# ==========================================
# LEVEL 2: BEARER TOKEN
# ==========================================
@app.route('/api/level/2/token', methods=['POST'])
def level_2_token():
    # Only allow Level 1 users to get a token
    auth = request.authorization
    if auth and auth.username == "username" and auth.password == "password":
        token = secrets.token_urlsafe(32)
        fail_tracker[token] = {"type": "bearer", "exp": time.time() + 300}
        return jsonify({"access_token": token, "token_type": "Bearer", "next": "/api/level/2"})
    return jsonify({"error": "Valid Level 1 credentials required via POST"}), 401

@app.route('/api/level/2', methods=['GET'])
def level_2():
    ip = get_remote_address()
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.replace('Bearer ', '')

    if token in fail_tracker and fail_tracker[token]['type'] == "bearer":
        msg = get_terminal_banner(2, "The bearer token is valid. Onward to Level 3.")
        return jsonify({"level": 2, "message": msg, "next": "/api/level/3/claim"})

    fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
    count = fail_tracker[ip]
    hints = {
        1: "You need an 'Authorization' header.",
        2: "The scheme is 'Bearer'. Use the token from the /token endpoint.",
        3: "Format: 'Authorization: Bearer <token_here>'"
    }
    return jsonify({"level": 2, "hint": hints.get(count, hints[3])}), 401

# ==========================================
# LEVEL 3: JWT (STAKEHOLDER IDENTITY)
# ==========================================
@app.route('/api/level/3/claim', methods=['POST'])
def level_3_claim():
    # Users must claim their role to get a JWT
    token = jwt.encode({
        "client_id": "username",
        "role": "player",
        "exp": datetime.utcnow() + timedelta(hours=1)
    }, JWT_SECRET, algorithm="HS256")
    return jsonify({"jwt": token, "hint": "Use this as a Bearer token at /api/level/3"})

@app.route('/api/level/3', methods=['GET'])
def level_3():
    ip = get_remote_address()
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        if payload.get("role") == "player":
            msg = get_terminal_banner(3, "JWT Identity Verified. Level 4 awaits.")
            return jsonify({"level": 3, "message": msg, "next": "/api/level/4"})
    except:
        pass

    fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
    count = fail_tracker[ip]
    hints = {
        1: "Level 3 uses a Signed JWT.",
        2: "Check the /api/level/3/claim endpoint.",
        3: "Decode the JWT at jwt.io to see your identity, then send it as a Bearer token."
    }
    return jsonify({"level": 3, "hint": hints.get(count, hints[3])}), 401

# ==========================================
# LEVEL 4: HMAC SIGNING
# ==========================================
@app.route('/api/level/4', methods=['GET'])
def level_4():
    ip = get_remote_address()
    sig = request.headers.get('X-Signature')
    ts = request.headers.get('X-Timestamp')
    key = derive_key("level4") # Hidden key
    
    if sig and ts:
        expected = hmac.new(key.encode(), f"GET{ts}".encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(sig, expected):
            msg = get_terminal_banner(4, "HMAC Integrity Verified. Final Gate reached.")
            return jsonify({"level": 4, "message": msg, "next": "/api/level/5"})

    fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
    count = fail_tracker[ip]
    hints = {
        1: "Integrity check required. Look for 'X-Signature' and 'X-Timestamp'.",
        2: "Key is the word 'username' hashed with the internal secret.", # Game specific clue
        3: "Signature is HMAC-SHA256 of 'GET' + current timestamp using the secret key."
    }
    return jsonify({"level": 4, "hint": hints.get(count, hints[3])}), 401

# ==========================================
# LEVEL 5: API KEY & VICTORY
# ==========================================
@app.route('/api/level/5', methods=['GET'])
def level_5():
    api_key = request.headers.get('X-API-Key')
    if api_key == derive_key("victory-key")[:16]:
        msg = get_terminal_banner(5, "VICTORY! ALL LEVELS passed!")
        return jsonify({"status": "passed", "message": msg, "flag": "FLAG{auth_gauntlet_master}"})

    ip = get_remote_address()
    fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
    count = fail_tracker[ip]
    hints = {
        1: "Final gate requires an 'X-API-Key'.",
        2: "The key is the first 16 chars of the Level 4 signature.",
        3: "Find the signature from Level 4 success and use it as X-API-Key."
    }
    return jsonify({"level": 5, "hint": hints.get(count, hints[3])}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)