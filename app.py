import hashlib
import secrets
import jwt
import hmac
import time
import logging
import os
from flask import Flask, jsonify, request, make_response
from datetime import datetime, timedelta
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# OpenTelemetry imports
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter

# Initialize OpenTelemetry
resource = Resource.create({
    "service.name": "k-api",
    "service.namespace": "default",
    "deployment.environment": "production"
})

# Setup tracing
trace.set_tracer_provider(TracerProvider(resource=resource))
tracer = trace.get_tracer(__name__)

# Configure OTLP trace exporter
otlp_trace_exporter = OTLPSpanExporter(
    endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector.logging.svc.cluster.local:4317"),
    insecure=True
)
span_processor = BatchSpanProcessor(otlp_trace_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

# Setup logging to OTel
logger_provider = LoggerProvider(resource=resource)
otlp_log_exporter = OTLPLogExporter(
    endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector.logging.svc.cluster.local:4317"),
    insecure=True
)
logger_provider.add_log_record_processor(BatchLogRecordProcessor(otlp_log_exporter))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add OTel handler to send logs to Loki
otel_handler = LoggingHandler(logger_provider=logger_provider)
logger.addHandler(otel_handler)

app = Flask(__name__)

# Auto-instrument Flask
FlaskInstrumentor().instrument_app(app)

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

def add_request_context_to_span(span):
    """Add common request context to span"""
    span.set_attribute("http.method", request.method)
    span.set_attribute("http.route", request.path)
    span.set_attribute("http.target", request.full_path)
    span.set_attribute("client.ip", get_remote_address())
    
    # Add select headers (avoid sensitive data)
    if request.headers.get('Authorization'):
        span.set_attribute("http.request.header.authorization_present", "true")
    if request.headers.get('X-API-Key'):
        span.set_attribute("http.request.header.x_api_key_present", "true")
    if request.headers.get('X-Identity-Token'):
        span.set_attribute("http.request.header.x_identity_token_present", "true")
    if request.headers.get('X-Signature'):
        span.set_attribute("http.request.header.x_signature_present", "true")
    if request.headers.get('X-Timestamp'):
        span.set_attribute("http.request.header.x_timestamp", request.headers.get('X-Timestamp'))

@app.before_request
def log_request():
    logger.info(f"Request: {request.method} {request.path} | IP: {get_remote_address()}")

@app.after_request
def log_response(response):
    logger.info(f"Response: {request.method} {request.path} | Status: {response.status_code} | IP: {get_remote_address()}")
    
    # Add response status to current span
    current_span = trace.get_current_span()
    if current_span:
        current_span.set_attribute("http.response.status_code", response.status_code)
    
    return response

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
    logger.info("Health check received")
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
    with tracer.start_as_current_span("level_1_auth") as span:
        add_request_context_to_span(span)
        
        ip = get_remote_address()
        auth = request.authorization
        
        span.set_attribute("level", 1)
        span.set_attribute("auth.type", "basic")
        span.set_attribute("auth.username_provided", bool(auth and auth.username))
        
        # SUCCESS: Reveal Level 2 Info
        if auth and auth.username == "api_hunter" and auth.password == "p@s5W0rD": # nosec B105
            fail_tracker.pop(ip, None) # Clear fails
            span.set_attribute("auth.result", "success")
            span.set_attribute("auth.username", auth.username)
            logger.info(f"LEVEL_1_SUCCESS | IP: {ip} | Username: {auth.username}")
            return jsonify({
                "status": "conquered",
                "next_level": "/api/level/2",
                "instruction": "Level 2 requires Custom Headers. Use X-API-Key and X-Identity-Token.",
                "creds": "Use the same username and password from Level 1."
            })

        # FAILURE: Progressive Hints
        fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
        count = fail_tracker[ip]
        span.set_attribute("auth.result", "failure")
        span.set_attribute("auth.fail_count", count)
        if auth and auth.username:
            span.set_attribute("auth.username_attempted", auth.username)
            logger.warning(f"LEVEL_1_FAILURE | IP: {ip} | Username: {auth.username} | Attempts: {count}")
        hints = {
            1: "Did you check the headers in Level 0? Look for 'X-Secret'.",
            2: "Level 1 uses Basic Auth. Use 'curl -u username:password'.",
            3: "The username is 'api_hunter' and the password is 'p@s5W0rD'." # nosec B105
        }
        res = make_response(jsonify({"hint": hints.get(count, hints[3])}), 401)
        res.headers['WWW-Authenticate'] = 'Basic realm="Level 1"'
        return res

# ==========================================
# LEVEL 2: BEARER TOKEN
# ==========================================
@app.route('/api/level/2', methods=['GET'])
def level_2():
    with tracer.start_as_current_span("level_2_auth") as span:
        add_request_context_to_span(span)
        
        ip = get_remote_address()
        api_key = request.headers.get('X-API-Key')
        identity = request.headers.get('X-Identity-Token')

        span.set_attribute("level", 2)
        span.set_attribute("auth.type", "custom_headers")
        span.set_attribute("auth.api_key_provided", bool(api_key))
        span.set_attribute("auth.identity_token_provided", bool(identity))

        # SUCCESS: Reveal Level 3 Info
        if api_key == "p@s5W0rD" and identity == "api_hunter":
            fail_tracker.pop(ip, None)
            span.set_attribute("auth.result", "success")
            span.set_attribute("auth.identity", identity)
            logger.info(f"LEVEL_2_SUCCESS | IP: {ip} | Identity: {identity}")
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
        span.set_attribute("auth.result", "failure")
        span.set_attribute("auth.fail_count", count)
        logger.warning(f"LEVEL_2_FAILURE | IP: {ip} | Attempts: {count}")
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
    with tracer.start_as_current_span("level_3_auth") as span:
        add_request_context_to_span(span)
        
        ip = get_remote_address()
        auth_header = request.headers.get('Authorization', '')

        span.set_attribute("level", 3)
        span.set_attribute("auth.type", "jwt")
        span.set_attribute("auth.bearer_token_provided", auth_header.startswith('Bearer '))

        # SUCCESS
        if auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]
            try:
                payload = jwt.decode(token, "p@s5W0rD", algorithms=["HS256"])
                span.set_attribute("auth.jwt_decoded", "true")
                span.set_attribute("auth.jwt_role", payload.get("role", ""))
                span.set_attribute("auth.jwt_user", payload.get("user", ""))
                
                if payload.get("role") == "admin":
                    span.set_attribute("auth.result", "success")
                    logger.info(f"LEVEL_3_SUCCESS | IP: {ip} | User: {payload.get('user')}")
                    return jsonify({"status": "conquered", "flag": "FLAG{auth_gauntlet_master}"})
                else:
                    span.set_attribute("auth.result", "failure")
                    span.set_attribute("auth.failure_reason", "insufficient_role")
                    logger.warning(f"LEVEL_3_FAILURE | IP: {ip} | Reason: insufficient_role")
            except jwt.ExpiredSignatureError:
                span.set_attribute("auth.result", "failure")
                span.set_attribute("auth.failure_reason", "token_expired")
                logger.warning(f"LEVEL_3_FAILURE | IP: {ip} | Reason: token_expired")
            except jwt.InvalidTokenError:
                span.set_attribute("auth.result", "failure")
                span.set_attribute("auth.failure_reason", "invalid_token")
                logger.warning(f"LEVEL_3_FAILURE | IP: {ip} | Reason: invalid_token")
            except Exception as e:
                span.set_attribute("auth.result", "failure")
                span.set_attribute("auth.failure_reason", f"exception_{type(e).__name__}")
                logger.warning(f"LEVEL_3_FAILURE | IP: {ip} | Reason: {type(e).__name__}")

        # FAILURE: Progressive Hints
        fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
        count = fail_tracker[ip]
        span.set_attribute("auth.result", "failure")
        span.set_attribute("auth.fail_count", count)
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
    with tracer.start_as_current_span("level_4_auth") as span:
        add_request_context_to_span(span)
        
        ip = get_remote_address()
        sig = request.headers.get('X-Signature')
        ts = request.headers.get('X-Timestamp')
        key = derive_key("level4") # Hidden key
        
        span.set_attribute("level", 4)
        span.set_attribute("auth.type", "hmac")
        span.set_attribute("auth.signature_provided", bool(sig))
        span.set_attribute("auth.timestamp_provided", bool(ts))
        
        if sig and ts:
            expected = hmac.new(key.encode(), f"GET{ts}".encode(), hashlib.sha256).hexdigest()
            span.set_attribute("auth.signature_match", hmac.compare_digest(sig, expected))
            
            if hmac.compare_digest(sig, expected):
                span.set_attribute("auth.result", "success")
                logger.info(f"LEVEL_4_SUCCESS | IP: {ip}")
                msg = get_terminal_banner(4, "HMAC Integrity Verified. Final Gate reached.")
                return jsonify({"level": 4, "message": msg, "next": "/api/level/5"})

        fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
        count = fail_tracker[ip]
        span.set_attribute("auth.result", "failure")
        span.set_attribute("auth.fail_count", count)
        logger.warning(f"LEVEL_4_FAILURE | IP: {ip} | Attempts: {count}")
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
    with tracer.start_as_current_span("level_5_auth") as span:
        add_request_context_to_span(span)
        
        api_key = # nosec B104request.headers.get('X-API-Key')
        
        span.set_attribute("level", 5)
        span.set_attribute("auth.type", "api_key")
        span.set_attribute("auth.api_key_provided", bool(api_key))
        
        if api_key == derive_key("victory-key")[:16]:
            span.set_attribute("auth.result", "success")
            ip = get_remote_address()
            logger.info(f"LEVEL_5_SUCCESS | IP: {ip} | VICTORY!")
            msg = get_terminal_banner(5, "VICTORY! ALL LEVELS passed!")
            return jsonify({"status": "passed", "message": msg, "flag": "FLAG{auth_gauntlet_master}"})

        ip = get_remote_address()
        fail_tracker[ip] = fail_tracker.get(ip, 0) + 1
        count = fail_tracker[ip]
        span.set_attribute("auth.result", "failure")
        span.set_attribute("auth.fail_count", count)
        logger.warning(f"LEVEL_5_FAILURE | IP: {ip} | Attempts: {count}")
        hints = {
            1: "Final gate requires an 'X-API-Key'.",
            2: "The key is the first 16 chars of the Level 4 signature.",
            3: "Find the signature from Level 4 success and use it as X-API-Key..."
        }
        return jsonify({"level": 5, "hint": hints.get(count, hints[3])}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080) # nosec B104