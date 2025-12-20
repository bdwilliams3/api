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
        "next_level": "/api/level/1",
        "hint": "Examine the response headers to find the password for the next gate."
    }))
    res.headers['X-Secret'] = 'p@s5W0rD'
    return res

# ==========================================
# LEVEL 1: PROGRESSIVE BASIC AUTH
# ==========================================
@app.route('/api/level/1', methods=['GET'])
def level_1():
    ip = get_remote_address()
    auth = request.authorization
    
    # SUCCESS: Reveal Level 2 Info
    if auth and auth.username == "api_hunter" and auth.password == "p@s5W0rD":
        fail_tracker.pop(ip, None) # Clear fails
        return jsonify({
            "status": "conquered",
            "next_level": "/api/level/2",
            "instruction": "Level 2 requires Custom Headers. Use X-API-Key and X-Identity-Token.",
            "creds": "Use the same username and password from Level 1."
        })

    # FAILURE: Progressive Hints
    fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
    count = fail_tracker[ip]
    hints = {
        1: "Did you check the headers in Level 0? Look for 'X-Secret'.",
        2: "Level 1 uses Basic Auth. Use 'curl -u username:password'.",
        3: "The username is 'api_hunter' and the password is 'p@s5W0rD'."
    }
    res = make_response(jsonify({"hint": hints.get(count, hints[3])}), 401)
    res.headers['WWW-Authenticate'] = 'Basic realm="Level 1"'
    return res

# ==========================================
# LEVEL 2: BEARER TOKEN
# ==========================================
@app.route('/api/level/2', methods=['GET'])
def level_2():
    ip = get_remote_address()
    api_key = request.headers.get('X-API-Key')
    identity = request.headers.get('X-Identity-Token')

    # SUCCESS: Reveal Level 3 Info
    if api_key == "p@s5W0rD" and identity == "api_hunter":
        fail_tracker.pop(ip, None)
        return jsonify({
            "status": "conquered",
            "next_level": "/api/level/3",
            "instruction": "Level 3 requires a JWT. Sign it with HS256.",
            "payload": {"user": "api_hunter", "role": "admin"},
            "secret_key": "p@s5W0rD"
        })

    # FAILURE: Progressive Hints
    fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
    count = fail_tracker[ip]
    hints = {
        1: "Basic Auth won't work here. You need to send custom 'X-' headers.",
        2: "You need 'X-API-Key' and 'X-Identity-Token'. Check Level 1's success message.",
        3: "Try: curl -H 'X-API-Key: p@s5W0rD' -H 'X-Identity-Token: api_hunter' ..."
    }
    return jsonify({"hint": hints.get(count, hints[3])}), 401

# ==========================================
# LEVEL 3: JWT (STAKEHOLDER IDENTITY)
# ==========================================
@app.route('/api/level/3', methods=['GET'])
def level_3():
    ip = get_remote_address()
    auth_header = request.headers.get('Authorization', '')

    # SUCCESS
    if auth_header.startswith('Bearer '):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, "p@s5W0rD", algorithms=["HS256"])
            if payload.get("role") == "admin":
                return jsonify({"status": "conquered", "flag": "FLAG{auth_gauntlet_master}"})
        except:
            pass

    # FAILURE: Progressive Hints
    fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
    count = fail_tracker[ip]
    hints = {
        1: "You need a Bearer token. Did you build the JWT as instructed in Level 2?",
        2: "The JWT must be signed with 'p@s5W0rD' and have the 'role' set to 'admin'.",
        3: "Use jwt.io to craft your token. Header: HS256, Payload: {'user':'api_hunter','role':'admin'}"
    }
    return jsonify({"hint": hints.get(count, hints[3])}), 401

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