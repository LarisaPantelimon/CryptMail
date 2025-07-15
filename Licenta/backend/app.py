import asyncio
from quart import Quart, request, jsonify, make_response, session, send_file
from quart_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token, unset_jwt_cookies,
    jwt_required, get_jwt_identity, get_raw_jwt, verify_jwt_in_request,
    set_access_cookies, set_refresh_cookies, jwt_refresh_token_required
)
from quart_cors import cors
import secrets
import smtplib
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import requests
from cryptography.fernet import Fernet
import ssl
from email.message import EmailMessage
import json
from datetime import datetime, timezone
import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from datetime import timedelta
import os
import socket
import logging
from DBquery import *

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Quart app
app = Quart(__name__)
app.config['JWT_SECRET_KEY'] = '8838232fa04b72cba34c85c61d09469547fd9c56b96b314d49a87dd5d5eedb90'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/'
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_SECURE'] = True
app.config['JWT_COOKIE_HTTPONLY'] = True
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_ACCESS_CSRF_COOKIE_HTTPONLY'] = False
app.config['JWT_REFRESH_CSRF_COOKIE_HTTPONLY'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200MB limit

load_dotenv()
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
MOBILE_SERVER_PORT = os.getenv("MOBILE_SERVER_PORT")
MOBILE_SERVER_IP = os.getenv("MOBILE_SERVER_IP")
MOBILE_SERVER_URL = "http://mobile-backend:6000/receive-data"
MY_SMTP_SERVER=os.getenv("MY_SMTP_SERVER")
MY_SMTP_PORT=os.getenv("MY_SMTP_PORT")

app.secret_key = os.urandom(24)
db = Database()

# Encryption key
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

jwt = JWTManager(app)
app = cors(
    app,
    allow_origin=["http://10.13.41.61","http://cryptmail.stud.fsisc.ro"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "x-csrf-token"],
    allow_credentials=True,
    expose_headers=["Access-Control-Allow-Origin"]
)

# Concurrency controls
session_lock = asyncio.Lock()
db_lock = asyncio.Lock()
refresh_token_store = {} 

@app.after_request
async def add_csp_header(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://trustedcdn.com;"
    return response

@app.route('/')
async def serve_react():
    return await send_file('static/index.html')

async def communicate_with_imap_server(data):
    async with db_lock:
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(MY_SMTP_SERVER, 993, ssl=ssl_context)
        writer.write(json.dumps(data).encode() + b'\n')
        await writer.drain()

        response_data = b""
        while True:
            try:
                chunk = await asyncio.wait_for(reader.read(1048576), timeout=1)
                response_data += chunk
                if not chunk:
                    break
            except asyncio.TimeoutError:
                logger.warning("IMAP read operation timed out")
                break

        try:
            response = json.loads(response_data.decode())
        except json.JSONDecodeError:
            response = {"success": False, "error": "Invalid response format from IMAP server"}

        writer.close()
        await writer.wait_closed()
        return response

async def communicate_with_smtp_server(data):
    async with db_lock:
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.open_connection(MY_SMTP_SERVER, 587, ssl=ssl_context)
        writer.transport.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
        data_bytes = json.dumps(data).encode() + b'\n'
        logger.info(f"Writing {len(data_bytes)} bytes to SMTP server")
        writer.write(data_bytes)
        await writer.drain()

        response_data = b""
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            response_data += chunk
            if b"\r\n" in response_data:
                break
        try:
            response = json.loads(response_data.decode())
        except json.JSONDecodeError:
            response = {"success": False, "error": "Invalid response format from SMTP server"}

        writer.close()
        await writer.wait_closed()
        return response

@app.route('/api/login', methods=['POST'])
async def login():
    data = await request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    logger.info(f"Processing login for {email}")
    async with db_lock:
        response_db = await handle_auth_request(db, email, password)

    if response_db.get("success"):
        async with session_lock:
            session_key = secrets.token_hex(32)
            session["session_key"] = session_key

        access_token = create_access_token(
            identity=email,
            user_claims={"isAdmin": email == "pantelimon.larisa30@cryptmail.ro"}
        )
        
        refresh_token = create_refresh_token(
            identity=email,
            user_claims={"isAdmin": email == "pantelimon.larisa30@cryptmail.ro"}
        )
        
        refresh_token_store[email] = refresh_token

        response = await make_response(jsonify({
            "message": "Login successful",
            "isAdmin": email == "pantelimon.larisa30@cryptmail.ro",
            "two_factor": response_db.get("two_factor"),
        }))
        print(access_token)
        set_access_cookies(response, access_token)
        set_refresh_cookies(response, refresh_token)
        return response
    else:
        return jsonify({"error": response_db.get("error"), "details": response_db.get("error")}), 401
    
    
@app.route('/api/refresh', methods=['OPTIONS'])
async def refresh_options():
    response = await make_response()
    response.headers['Access-Control-Allow-Origin'] = 'http://10.13.41.61'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-csrf-token, X-CSRF-TOKEN'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Max-Age'] = '86400'
    logger.info("Handled OPTIONS request for /refresh")
    return response
@app.route('/api/refresh', methods=['POST'])
@jwt_refresh_token_required
async def refresh():
    current_user = get_jwt_identity()
    stored_token = refresh_token_store.get(current_user)

    # Verify the refresh token
    if not stored_token or stored_token != get_raw_jwt()['jti']:
        return jsonify({"message": "Invalid refresh token"}), 401

    # Create new access token with is_admin claim
    new_access_token = create_access_token(
        identity=current_user,
        user_claims={"isAdmin": current_user == "pantelimon.larisa30@cryptmail.ro"}
    )

    response = await make_response(jsonify({"message": "Token refreshed"}))
    set_access_cookies(response, new_access_token)
    return response

@app.route('/api/register', methods=['POST'])
async def register():
    form_data = await request.get_json()
    email = form_data.get('email')
    password = form_data.get('password')
    full_name = form_data.get('fullName')
    phone_number = form_data.get('phoneNumber')
    gender = form_data.get('gender')
    birthday = form_data.get('birthday')
    public_key_pem = form_data.get('publicKeyPem')
    encrypted_private_key = form_data.get('privateKeyPem')
    twoFactor = form_data.get('twoFactorAuth')

    timestamp = datetime.now(timezone.utc).isoformat()
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    lsb_64_bits = int.from_bytes(public_key_der[-8:], byteorder='big')

    payload = {
        "action": "register",
        "email": email,
        "password": password,
        "fullName": full_name,
        "phoneNumber": phone_number,
        "gender": gender,
        "birthday": birthday,
        "public_key": public_key_pem,
        "private_key": encrypted_private_key,
        "timestamp": timestamp,
        "key_id": str(lsb_64_bits),
        "twoFactor": twoFactor,
    }

    async with db_lock:
        response_db = await handle_register(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Registered successfully"}), 200
    else:
        logger.error(f"Registration failed: {response_db.get('error')}")
        return jsonify({"error": "Failed to retrieve PubKey and KeyId", "details": response_db.get("error")}), 500

@app.route('/api/get-email', methods=['GET'])
async def get_email():
    try:
        await verify_jwt_in_request()
        email = get_jwt_identity()
        return jsonify({"email": email})
    except Exception as e:
        logger.error(f"JWT validation failed: {e}")
        return jsonify({"error": "Not authenticated"}), 401

@app.route('/api/get-session-key', methods=['OPTIONS'])
async def get_session_key_options():
    # Lista originilor permise
    allowed_origins = ['http://cryptmail.stud.fsisc.ro', 'http://10.13.41.61']
    
    # Ob?ine originea cererii din header-ul Origin
    origin = request.headers.get('Origin')
    
    # Verifica daca originea cererii este permisa
    if origin in allowed_origins:
        response = await make_response()
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-csrf-token, X-CSRF-TOKEN'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        response.headers['Access-Control-Max-Age'] = '86400'
        logger.info(f"Handled OPTIONS request for /get-session-key from {origin}")
        return response
    else:
        logger.warning(f"Blocked OPTIONS request for /get-session-key from unallowed origin: {origin}")
        return jsonify({"error": "Origin not allowed"}), 403
@app.route('/api/get-session-key', methods=['POST'])
@jwt_required
async def get_session_key():
    email = get_jwt_identity()
    if not email:
        logger.error("User not authenticated")
        return jsonify({"error": "Unauthorized! You need to be connected"}), 401

    async with session_lock:
        if not session.get("session_key"):
            logger.error("Session key not found")
            return jsonify({"error": "Unauthorized"}), 401
        return jsonify({"sessionKey": session["session_key"]})

@app.route('/api/get-all-privatekeys', methods=['POST'])
@jwt_required
async def get_all_privatekeys():
    data = await request.get_json()
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_all_privatekeys(db, payload)

    if response_db.get("success"):
        private_keys = response_db.get("PrivateKeys")
        return jsonify({"PrivateKeys": private_keys})
    else:
        logger.error(f"Failed to fetch private keys: {response_db.get('error')}")
        return jsonify({"error": "Failed to fetch private keys from DB", "details": response_db.get("error")}), 500

@app.route('/api/get-last-key', methods=['POST'])
@jwt_required
async def get_last_key():
    data = await request.get_json()
    receiver_email = data.get("receiver_email")

    if not receiver_email:
        return jsonify({"error": "Receiver email is required"}), 400

    payload = {"receiver_email": receiver_email}
    async with db_lock:
        response_db = await handle_get_last_key(db, payload)

    if response_db.get("success"):
        return jsonify({
            "PublicKey": response_db["PubKey"],
            "KeyId": response_db["KeyId"],
            "ExpirationDate": response_db["ExpirationDate"],
        })
    else:
        return jsonify({
            "PublicKey": None,
            "KeyId": None,
            "ExpirationDate": None
        })

@app.route('/api/get-myprivatekey', methods=['POST'])
@jwt_required
async def get_myprivatekey():
    data = await request.get_json()
    email = get_jwt_identity()
    key_id = data.get("key_id")

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email": email, "key_id": key_id}
    async with db_lock:
        response_db = await handle_get_myprivatekey(db, payload)

    if response_db.get("success"):
        return jsonify({"PrivateKey": response_db["PrivateKey"]})
    else:
        logger.error(f"Failed to fetch private key: {response_db.get('error')}")
        return jsonify({"error": "Failed to fetch private key", "details": response_db.get("error")}), 500

@app.route('/api/get-receiver-key', methods=['POST'])
@jwt_required
async def get_receiver_key():
    data = await request.get_json()
    receiver_email = data.get("receiver_email")
    key_id = data.get("key_id")

    if not receiver_email:
        return jsonify({"error": "Receiver email is required"}), 400

    payload = {"receiver_email": receiver_email, "key_id": key_id}
    async with db_lock:
        response_db = await handle_get_pubKey(db, payload)

    if response_db.get("success"):
        return jsonify({"PublicKey": response_db["PubKey"]})
    else:
        logger.error(f"Failed to fetch public key: {response_db.get('error')}")
        return jsonify({"error": "Failed to fetch public key", "details": response_db.get("error")}), 500


@app.route('/api/inbox/send-email', methods=['OPTIONS'])
async def send_email_options():
    response = await make_response()  # Await the coroutine
    response.headers['Access-Control-Allow-Origin'] = 'http://10.13.41.61'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-csrf-token'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Max-Age'] = '86400'  # Cache preflight for 24 hours
    logger.info("Handled OPTIONS request for /inbox/send-email")
    return response

@app.route('/api/inbox/send-email', methods=['POST'])
@jwt_required
async def send_email():
    current_user = get_jwt_identity()
    content_length = request.content_length or 0
    logger.info(f"Request body size for {current_user}: {content_length} bytes")
    if content_length > app.config['MAX_CONTENT_LENGTH']:
        logger.error(f"Payload too large: {content_length} bytes exceeds {app.config['MAX_CONTENT_LENGTH']} bytes")
        return jsonify({"error": "Payload too large", "details": f"Request size {content_length} exceeds limit {app.config['MAX_CONTENT_LENGTH']}"}), 413

    data = await request.get_json()
    from_email = data.get("from")
    to_email = data.get("to")
    mime_message = data.get("mime_message")
    subject = data.get("subject")
    mime_message_for_me = data.get("mime_message_for_me")

    if not from_email or not to_email or not mime_message:
        logger.error(f"Missing required fields for {current_user}")
        return jsonify({"error": "Missing required email fields"}), 400

    payload = {"from": from_email, "to": to_email, "subject": subject}
    async with db_lock:
        response_db = await handle_send_email(db, payload)

    if response_db.get("success"):
        email_id_sent = response_db.get("email_id_sent")
        email_id_received = response_db.get("email_id_received")
        payload = {
            "action": "send_email",
            "email_id_sent": email_id_sent,
            "email_id_received": email_id_received,
            "mime_message": mime_message,
            "mime_message_for_me": mime_message_for_me
        }
        smtp_response = await communicate_with_smtp_server(payload)

        if smtp_response.get("success"):
            logger.info(f"Email sent successfully from {current_user} to {to_email}")
            return jsonify({"message": "Email sent successfully"}), 200
        else:
            logger.error(f"SMTP error for {current_user}: {smtp_response.get('error')}")
            return jsonify({"error": "Failed to send email", "details": smtp_response.get("error")}), 500
    else:
        logger.error(f"DB error for {current_user}: {response_db.get('error')}")
        return jsonify({"error": "Failed to send email", "details": response_db.get("error")}), 500
@app.route('/api/inbox/fetch-email-content', methods=['POST'])
@jwt_required
async def fetch_email_content():
    email = get_jwt_identity()
    data = await request.get_json()
    email_id = data.get("email_id")
    folder = data.get("folder")

    if not email:
        return jsonify({"error": "You need to be authenticated!"}), 400
    if not email_id or not folder:
        return jsonify({"error": "EmailId or Folder MISSING!"}), 400

    payload = {"action": "fetch_email_content", "email_id": email_id, "folder": folder}
    imap_response = await communicate_with_imap_server(payload)

    if imap_response.get("success"):
        email_content = imap_response.get("MimeMessage")
        return jsonify({"MimeMessage": email_content})
    else:
        logger.error(f"IMAP error: {imap_response.get('error')}")
        return jsonify({"error": "Failed to fetch email content", "details": imap_response.get("error")}), 500

@app.route('/api/inbox/fetch-emails', methods=['POST'])
@jwt_required
async def fetch_emails():
    data = await request.get_json()
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_fetch_emails(db, payload)

    if response_db.get("success"):
        emails_sent = response_db.get("emails_sent")
        emails_received = response_db.get("emails_received")
        email_data = []

        for email_info in emails_sent:
            email_data.append({
                "EmailID": email_info.get('EmailSentId', 'Unknown ID'),
                "Sender": email_info.get('Sender', 'Unknown Sender'),
                "Receiver": email_info.get('Receiver', 'Unknown Recipient'),
                "SentDate": email_info.get('SentDate', 'Unknown Date'),
                "IsRead": email_info.get('IsRead', False),
                "Folder": email_info.get('Folder', 'Inbox'),
                "Subject": email_info.get('Subject', 'No Subject'),
                "sent": 1,
                "received": 0
            })

        for email_info in emails_received:
            email_data.append({
                "EmailID": email_info.get('EmailReceivedId', 'Unknown ID'),
                "Sender": email_info.get('Sender', 'Unknown Sender'),
                "Receiver": email_info.get('Receiver', 'Unknown Recipient'),
                "SentDate": email_info.get('SentDate', 'Unknown Date'),
                "IsRead": email_info.get('IsRead', False),
                "Folder": email_info.get('Folder', 'Inbox'),
                "Subject": email_info.get('Subject', 'No Subject'),
                "sent": 0,
                "received": 1
            })

        return jsonify({"emails": email_data})
    else:
        logger.error(f"Failed to fetch emails: {response_db.get('error')}")
        return jsonify({"error": "Failed to fetch emails from DB", "details": response_db.get("error")}), 500

@app.route('/api/inbox/mark-email-read', methods=['POST'])
@jwt_required
async def mark_email_read():
    data = await request.get_json()
    email_id = data.get("emailId")
    sender = data.get("sender")
    receiver = data.get("receiver")
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email_id": email_id, "email": email, "sender": sender, "receiver": receiver}
    async with db_lock:
        response_db = await handle_mark_email_read(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Email marked as read successfully"}), 200
    else:
        logger.error(f"Failed to mark email as read: {response_db.get('error')}")
        return jsonify({"error": "Failed to mark email as read", "details": response_db.get("error")}), 500
    
@app.route('/api/inbox/update-email', methods=['OPTIONS'])
async def update_email_options():
    response = await make_response()
    response.headers['Access-Control-Allow-Origin'] = 'http://10.13.41.61'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-csrf-token, X-CSRF-TOKEN'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Max-Age'] = '86400'
    logger.info("Handled OPTIONS request for /inbox/update-email")
    return response

@app.route('/api/inbox/update-email', methods=['POST'])
@jwt_required
async def update_email():
    data = await request.get_json()
    email_id = data.get("emailId")
    newfolder = data.get("action")
    useremail = data.get("email")
    senderemail = data.get("sender")
    receiver = data.get("receiver")
    
    print(newfolder)

    payload = {
        "email_id": email_id,
        "newfolder": newfolder,
        "myemail": useremail,
        "sender": senderemail,
        "receiver": receiver
    }

    async with db_lock:
        response_db = await handle_update_folder(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Folder changed successfully"}), 200
    else:
        logger.error(f"Failed to update folder: {response_db.get('error')}")
        return jsonify({"error": "Failed to update folder", "details": response_db.get("error")}), 500

@app.route('/api/inbox/delete-email', methods=['POST'])
@jwt_required
async def delete_email():
    data = await request.get_json()
    email_id = data.get("emailId")
    email = get_jwt_identity()
    sender = data.get("sender")
    receiver = data.get("receiver")

    payload = {"email_id": email_id, "email": email, "sender": sender, "receiver": receiver}
    async with db_lock:
        response_db = await handle_delete_email(db, payload)

    if response_db.get("success"):
        payload = {
            "action": "delete_email",
            "email_id": email_id,
            "email": email,
            "sender": sender,
            "receiver": receiver
        }
        imap_response = await communicate_with_imap_server(payload)

        if imap_response.get("success"):
            return jsonify({"message": "Email deleted successfully"}), 200
        else:
            logger.error(f"IMAP error: {imap_response.get('error')}")
            return jsonify({"error": "Failed to delete email from AWS", "details": imap_response.get("error")}), 500
    else:
        logger.error(f"DB error: {response_db.get('error')}")
        return jsonify({"error": "Failed to delete email from DB", "details": response_db.get("error")}), 500

@app.route('/api/user', methods=['POST'])
@jwt_required
async def get_user():
    data = await request.get_json()
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_user(db, payload)

    if response_db.get("success"):
        user_data = {
            "Email": response_db.get("email"),
            "FullName": response_db.get("fullName"),
            "PhoneNumber": response_db.get("phoneNumber"),
            "Birthday": response_db.get("birthday"),
            "Gender": response_db.get("gender")
        }
        return jsonify({"user": user_data})
    else:
        logger.error(f"Failed to fetch user: {response_db.get('error')}")
        return jsonify({"error": "Failed to fetch user from DB", "details": response_db.get("error")}), 500

@app.route('/api/update-user', methods=['POST'])
@jwt_required
async def user_update():
    data = await request.get_json()
    old_email = data.get('oldEmail')
    updated_user = data.get('updatedUser')

    if not old_email:
        return jsonify({'error': 'Old email is required to update user data'}), 400
    if not updated_user:
        return jsonify({'error': 'No user data provided'}), 400

    payload = {"oldEmail": old_email, "updatedUser": updated_user}
    async with db_lock:
        response_db = await handle_update_user(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "User data updated successfully"}), 200
    else:
        logger.error(f"Failed to update user: {response_db.get('error')}")
        return jsonify({"error": "Failed to update user data in DB", "details": response_db.get("error")}), 500

@app.route('/api/update-password', methods=['POST'])
@jwt_required
async def update_password():
    data = await request.get_json()
    email = get_jwt_identity()
    old_password = data.get("oldPassword")
    new_password = data.get("newHashedPassword")
    private_keys = data.get("encryptedPrivateKeys")

    if not email or not old_password or not new_password or not private_keys:
        return jsonify({"error": "Email, old password, new password, and private key are required"}), 400

    payload = {
        "email": email,
        "old_password": old_password,
        "newHashedPassword": new_password,
        "private_keys": private_keys
    }

    async with db_lock:
        response_db = await handle_update_password(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Password updated successfully"}), 200
    else:
        logger.error(f"Failed to update password: {response_db.get('error')}")
        return jsonify({"error": "Failed to update password", "details": response_db.get("error")}), 500


@app.route('/api/generate-newkeys', methods=['OPTIONS'])
async def generate_newkeys_options():
    response = await make_response()  # Await the coroutine for async compatibility
    response.headers['Access-Control-Allow-Origin'] = 'http://10.13.41.61'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-csrf-token, X-CSRF-TOKEN'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Max-Age'] = '86400'  # Cache preflight for 24 hours
    logger.info("Handled OPTIONS request for /generate-newkeys")
    return response
@app.route('/api/generate-newkeys', methods=['POST'])
@jwt_required
async def generate_newkeys():
    data = await request.get_json()
    email = get_jwt_identity()
    public_key_pem = data.get('publicKeyPem')
    encrypted_private_key = data.get('privateKeyPem')

    if not email or not public_key_pem or not encrypted_private_key:
        return jsonify({"error": "Email and the keys are required"}), 400

    timestamp = datetime.now(timezone.utc).isoformat()
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    lsb_64_bits = int.from_bytes(public_key_der[-8:], byteorder='big')

    payload = {
        "email": email,
        "encryptedPrivateKey": encrypted_private_key,
        "publicKeyPem": public_key_pem,
        "timestamp": timestamp,
        "key_id": str(lsb_64_bits)
    }

    async with db_lock:
        response_db = await handle_generate_newkeys(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "New keys generated successfully", "publicKeyPem": public_key_pem}), 200
    else:
        logger.error(f"Failed to generate new keys: {response_db.get('error')}")
        return jsonify({"error": "Failed to generate new keys", "details": response_db.get("error")}), 500

@app.route('/api/save-recovery-email', methods=['POST'])
@jwt_required
async def save_recovery_email():
    data = await request.get_json()
    email = get_jwt_identity()
    recovery_email = data.get('recovery_email')

    if not email or not recovery_email:
        return jsonify({"error": "Email and recovery email are required"}), 400

    payload = {"email": email, "recovery_email": recovery_email}
    async with db_lock:
        response_db = await handle_save_recovery_email(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Email saved!"}), 200
    else:
        logger.error(f"Failed to save recovery email: {response_db.get('error')}")
        return jsonify({"error": "Failed to save email", "details": response_db.get("error")}), 500

@app.route('/api/update-recovery-email', methods=['POST'])
@jwt_required
async def update_recovery_email():
    data = await request.get_json()
    email = get_jwt_identity()
    recovery_email = data.get('recovery_email')

    if not email or not recovery_email:
        return jsonify({"error": "Email and recovery email are required"}), 400

    payload = {"email": email, "recovery_email": recovery_email}
    async with db_lock:
        response_db = await handle_update_recovery_email(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Email updated!"}), 200
    else:
        logger.error(f"Failed to update recovery email: {response_db.get('error')}")
        return jsonify({"error": "Failed to update email", "details": response_db.get("error")}), 500

@app.route('/api/get-recovery-email', methods=['POST'])
async def get_recovery_email():
    data = await request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_recovery_email(db, payload)

    if response_db.get("success"):
        return jsonify({
            "message": "Email received!",
            "verification": response_db.get("verification"),
            "recovery_email": response_db.get("recovery_email")
        }), 200
    else:
        logger.error(f"Failed to get recovery email: {response_db.get('error')}")
        return jsonify({"error": "Failed to get email", "details": response_db.get("error")}), 500

@app.route('/api/verify-email', methods=['POST'])
async def verify_email():
    data = await request.get_json()
    email = data.get('email')
    code = data.get('code')

    if not email or not code:
        return jsonify({"error": "Email and code are required"}), 400

    subject = "Your Verification Code"
    body = f"Your verification code is: {code}"
    message = f"Subject: {subject}\n\n{body}"

    try:
        server = smtplib.SMTP_SSL(SMTP_SERVER, 465)
        server.set_debuglevel(1)
        logger.info("Connected to SMTP server")
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        logger.info("Logged in to SMTP server")
        server.sendmail(EMAIL_ADDRESS, email, message)
        logger.info("Email sent successfully")
        server.quit()
        return jsonify({"message": "Verification email sent!"})
    except Exception as e:
        logger.error(f"Error sending email: {str(e)}")
        return jsonify({"error": "Failed to send verification email"}), 500

@app.route('/api/marked-verified', methods=['POST'])
@jwt_required
async def mark_ver_email():
    data = await request.get_json()
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_mark_recovery_email(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Email verified!"}), 200
    else:
        logger.error(f"Failed to verify email: {response_db.get('error')}")
        return jsonify({"error": "Failed to verify email", "details": response_db.get("error")}), 500

@app.route('/api/check-recovery-file', methods=['POST'])
@jwt_required
async def check_recovery_file():
    data = await request.get_json()
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_check_recovery_file(db, payload)

    if response_db.get("success"):
        return jsonify({
            "message": "File verified!",
            "exists": response_db.get("exists"),
            "fileUsed": response_db.get("fileUsed", False)
        }), 200
    else:
        logger.error(f"Failed to check recovery file: {response_db.get('error')}")
        return jsonify({"error": "Failed to check recovery file", "details": response_db.get("error")}), 500

@app.route('/api/generate-recovery-file', methods=['POST'])
@jwt_required
async def generate_recovery_file():
    data = await request.get_json()
    email = get_jwt_identity()
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    payload = {"email": email, "password": password}
    async with db_lock:
        response_db = await handle_generate_recovery_file(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "File successfully generated!"}), 200
    else:
        logger.error(f"Failed to generate recovery file: {response_db.get('error')}")
        return jsonify({"error": "Failed to generate file", "details": response_db.get("error")}), 500

@app.route('/api/delete-recovery-file', methods=['POST'])
@jwt_required
async def delete_recovery_file():
    data = await request.get_json()
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_delete_recovery_file(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "File successfully deleted!"}), 200
    else:
        logger.error(f"Failed to delete recovery file: {response_db.get('error')}")
        return jsonify({"error": "Failed to delete file", "details": response_db.get("error")}), 500

@app.route('/api/set-new-password', methods=['POST'])
async def set_new_password():
    data = await request.get_json()
    email = data.get("email")
    private_key = data.get("private_key")
    public_key_pem = data.get("public_key")
    hashed_password = data.get("hashed_password")

    if not email or not private_key or not public_key_pem or not hashed_password:
        return jsonify({"error": "Email, keys and hashed password are required"}), 400

    timestamp = datetime.now(timezone.utc).isoformat()
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )

    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    lsb_64_bits = int.from_bytes(public_key_der[-8:], byteorder='big')

    payload = {
        "email": email,
        "private_key": private_key,
        "public_key": public_key_pem,
        "hashed_password": hashed_password,
        "timestamp": timestamp,
        "key_id": str(lsb_64_bits)
    }

    async with db_lock:
        response_db = await handle_set_new_password(db, payload)

    payload={"email": email, "user_email":email}
    async with db_lock:
        response_db_new = await handle_disable_2fa(db, payload)

    if response_db.get("success") and response_db_new.get("success"):
        return jsonify({"message": "Credentials updated for forgot password!"}), 200
    else:
        logger.error(f"Failed to set new password: {response_db.get('error')}")
        return jsonify({"error": "Failed to update for forgot password", "details": response_db.get("error")}), 500

@app.route('/api/check-status', methods=['POST'])
@jwt_required
async def check_status():
    data = await request.get_json()
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_check_status(db, payload)

    if response_db.get("success"):
        return jsonify({
            "message": "Credentials updated for forgot password!",
            "Flag_Reset": response_db.get("Flag_Reset")
        }), 200
    else:
        logger.error(f"Failed to check status: {response_db.get('error')}")
        return jsonify({"error": "Failed to check status", "details": response_db.get("error")}), 500

@app.route('/api/get-key-for-recovery', methods=['POST'])
@jwt_required
async def get_key_for_recovery():
    data = await request.get_json()
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_key_for_recovery(db, payload)

    if response_db.get("success"):
        return jsonify({
            "message": "Credentials updated for forgot password!",
            "key": response_db.get("key")
        }), 200
    else:
        logger.error(f"Failed to get key for recovery: {response_db.get('error')}")
        return jsonify({"error": "Failed to get key for recovery", "details": response_db.get("error")}), 500

@app.route('/api/recover-all-keys', methods=['POST'])
@jwt_required
async def recover_all_keys():
    data = await request.get_json()
    email = get_jwt_identity()
    rencKeys = data.get('rencKeys')

    if not email or not rencKeys:
        return jsonify({"error": "Email and re-encrypted keys are required"}), 400

    payload = {"email": email, "rencKeys": rencKeys}
    async with db_lock:
        response_db = await handle_recover_all_keys(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "The keys were recovered successfully!"}), 200
    else:
        logger.error(f"Failed to recover keys: {response_db.get('error')}")
        return jsonify({"error": "Failed to recover the keys!", "details": response_db.get("error")}), 500

@app.route('/api/check-auth', methods=['GET'])
@jwt_required
async def check_auth():
    email = get_jwt_identity()
    if email:
        is_admin = email == "larisa.pantelimon@cryptmail.ro"
        return jsonify({'authenticated': True, 'email': email, 'isAdmin': is_admin}), 200
    return jsonify({
        'authenticated': False,
        'email': None,
        'isAdmin': False
    }), 200

@app.route('/api/update-2fa', methods=['POST'])
@jwt_required
async def update_2fa():
    data = await request.get_json()
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_update_2fa(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "2FA updated successfully!"}), 200
    else:
        logger.error(f"Failed to update 2FA: {response_db.get('error')}")
        return jsonify({"error": "Failed to update 2FA", "details": response_db.get("error")}), 500

@app.route('/api/get-2fa-info', methods=['POST'])
@jwt_required
async def get_2fa_info():
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_2fa_info(db, payload)

    if response_db.get("success"):
        return jsonify({
            "message": "2FA info retrieved successfully!",
            "PublicKey": response_db.get("PublicKey"),
            "PrivateKey": response_db.get("PrivateKey"),
            "PublicKeyMobile": response_db.get("PublicKeyMobile")
        }), 200
    else:
        logger.error(f"Failed to retrieve 2FA info: {response_db.get('error')}")
        return jsonify({"error": "Failed to retrieve 2FA info", "details": response_db.get("error")}), 500

@app.route('/api/send-data-to-mobile', methods=['POST'])
@jwt_required
async def send_data_to_mobile():
    data = await request.get_json()
    email = get_jwt_identity()
    randomString = data.get("randomString")
    signedHash = data.get("signedHash")
    encM = data.get("encM")
    c = data.get("c")

    if not email or not signedHash or not encM or not c:
        return jsonify({"error": "Email, signed hash, encrypted string, and c are required"}), 400

    payload = {
        "email": email,
        "signedHash": signedHash,
        "encM": encM,
        "c": c,
        "randomString": randomString
    }

    try:
        response = requests.post(MOBILE_SERVER_URL, json=payload, timeout=35)
        response.raise_for_status()
        return jsonify(response.json()), 200
    except requests.RequestException as e:
        logger.error(f"Error sending data to mobile: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/data-from-mobile', methods=['POST'])
async def process_mobile_data():
    data = await request.get_json()
    action = data.get("action")
    email = data.get("email")
    ownerEmail = data.get("ownerEmail")

    if action == "save":
        publicKey = data.get("publicKey")
        payload = {"email": email, "ownerEmail": ownerEmail, "publicKey": publicKey}
        async with db_lock:
            response_db = await handle_save_mobile_data(db, payload)

        if response_db.get("success"):
            return jsonify({"message": "Data saved successfully!"}), 200
        else:
            logger.error(f"Failed to save mobile data: {response_db.get('error')}")
            return jsonify({"error": "Failed to save data", "details": response_db.get("error")}), 500

@app.route('/api/inbox/mark-email-unread', methods=['POST'])
@jwt_required
async def mark_email_unread():
    data = await request.get_json()
    email_id = data.get("emailId")
    sender = data.get("sender")
    receiver = data.get("receiver")
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email_id": email_id, "email": email, "sender": sender, "receiver": receiver}
    async with db_lock:
        response_db = await handle_mark_email_unread(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Email marked as unread successfully"}), 200
    else:
        logger.error(f"Failed to mark email as unread: {response_db.get('error')}")
        return jsonify({"error": "Failed to mark email as unread", "details": response_db.get("error")}), 500

@app.route('/api/inbox/add-contact', methods=['POST'])
@jwt_required
async def add_contact():
    data = await request.get_json()
    email = get_jwt_identity()
    contact_email = data

    if not email or not contact_email:
        return jsonify({"error": "Email and contact email are required"}), 400

    payload = {"email": email, "contact_email": contact_email}
    async with db_lock:
        response_db = await handle_add_contact(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Contact added successfully"}), 200
    else:
        logger.error(f"Failed to add contact: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/inbox/get-contacts', methods=['GET'])
@jwt_required
async def get_contacts():
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_contacts(db, payload)

    if response_db.get("success"):
        contacts = response_db.get("contacts", [])
        return jsonify({"contacts": contacts}), 200
    else:
        logger.error(f"Failed to retrieve contacts: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/inbox/delete-contact', methods=['POST'])
@jwt_required
async def delete_contact():
    data = await request.get_json()
    email = get_jwt_identity()
    contact_email = data

    if not email or not contact_email:
        return jsonify({"error": "Email and contact email are required"}), 400

    payload = {"email": email, "contact_email": contact_email}
    async with db_lock:
        response_db = await handle_delete_contact(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Contact deleted successfully"}), 200
    else:
        logger.error(f"Failed to delete contact: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/inbox/add-folder', methods=['POST'])
@jwt_required
async def add_folder():
    data = await request.get_json()
    email = get_jwt_identity()
    folder_name = data

    if not email or not folder_name:
        return jsonify({"error": "Email and folder name are required"}), 400

    payload = {"email": email, "folder_name": folder_name}
    async with db_lock:
        response_db = await handle_add_folder(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Folder added successfully"}), 200
    else:
        logger.error(f"Failed to add folder: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/inbox/get-folders', methods=['GET'])
@jwt_required
async def get_folders():
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_folders(db, payload)

    if response_db.get("success"):
        folders = response_db.get("folders", [])
        return jsonify({"folders": folders}), 200
    else:
        logger.error(f"Failed to retrieve folders: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/inbox/delete-folder', methods=['POST'])
@jwt_required
async def delete_folder():
    data = await request.get_json()
    email = get_jwt_identity()
    folder_name = data

    if not email or not folder_name:
        return jsonify({"error": "Email and folder name are required"}), 400

    payload = {"email": email, "folder_name": folder_name}
    async with db_lock:
        response_db = await handle_delete_folder(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "Folder deleted successfully"}), 200
    else:
        logger.error(f"Failed to delete folder: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/admin-info', methods=['GET'])
@jwt_required
async def get_admin_info():
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_admin_info(db, payload)

    if response_db.get("success"):
        return jsonify({
            "success": True,
            "total_users": response_db.get("total_users"),
            "total_sent_emails": response_db.get("total_sent_emails"),
            "total_2fa_users": response_db.get("total_2fa_users"),
            "user_data": response_db.get("user_data")
        }), 200
    else:
        logger.error(f"Failed to retrieve admin info: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/admin-get-logs', methods=['GET'])
@jwt_required
async def get_admin_logs():
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_admin_logs(db, payload)

    if response_db.get("success"):
        logs = response_db.get("logs", [])
        return jsonify({"success": True, "logs": logs}), 200
    else:
        logger.error(f"Failed to retrieve admin logs: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/admin-get-users', methods=['GET'])
@jwt_required
async def get_admin_users():
    email = get_jwt_identity()

    if not email:
        return jsonify({"error": "Email address is required"}), 400

    payload = {"email": email}
    async with db_lock:
        response_db = await handle_get_admin_users(db, payload)

    if response_db.get("success"):
        users = response_db.get("users", [])
        return jsonify({"success": True, "users": users}), 200
    else:
        logger.error(f"Failed to retrieve admin users: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/admin-disable-2fa', methods=['POST'])
@jwt_required
async def disable_2fa():
    data = await request.get_json()
    email = get_jwt_identity()
    user_email = data

    if not email or not user_email:
        return jsonify({"error": "Email and user email are required"}), 400

    payload = {"email": email, "user_email": user_email}
    async with db_lock:
        response_db = await handle_disable_2fa(db, payload)

    if response_db.get("success"):
        return jsonify({"message": "2FA disabled successfully"}), 200
    else:
        logger.error(f"Failed to disable 2FA: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500

@app.route('/api/admin-delete-user', methods=['OPTIONS'])
async def delete_user_options():
    response = await make_response()
    response.headers['Access-Control-Allow-Origin'] = 'http://10.13.41.61'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-csrf-token, X-CSRF-TOKEN'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    response.headers['Access-Control-Max-Age'] = '86400'
    logger.info("Handled OPTIONS request for /admin-delete-user")
    return response
@app.route('/api/admin-delete-user', methods=['POST'])
@jwt_required
async def delete_user():
    data = await request.get_json()
    email = get_jwt_identity()
    user_email = data

    if not email or not user_email:
        return jsonify({"error": "Email and user email are required"}), 400

    payload = {"email": email, "user_email": user_email}
    async with db_lock:
        response_db = await handle_delete_user(db, payload)

    if response_db.get("success"):
        emails_sent_ids = response_db.get("deleted_emails_sent_ids")
        emails_received_ids = response_db.get("deleted_emails_received_ids")
        payload = {
            "action": "delete_emails_user",
            "email_user": user_email,
            "email_sent_ids": emails_sent_ids,
            "email_received_ids": emails_received_ids
        }
        imap_response = await communicate_with_imap_server(payload)

        if imap_response.get("success"):
            return jsonify({"message": "Emails deleted successfully"}), 200
        else:
            logger.error(f"IMAP error: {imap_response.get('error')}")
            return jsonify({"error": "Failed to delete emails from AWS", "details": imap_response.get("error")}), 500
    else:
        logger.error(f"DB error: {response_db.get('error')}")
        return jsonify({"error": response_db.get("error")}), 500
    
@app.route('/api/2fa-state',methods=['GET'])
@jwt_required
async def get_2fa_state():
    email = get_jwt_identity()
    
    if not email:
        return jsonify({"error": "Email is required"}), 400
    payload = {"email": email}
    async with db_lock:
        response_db=await handle_get_2fa_state(db,payload)
    if response_db.get("success"):
        return jsonify({"success":True, "get2fa":response_db.get("2fa")})
    else:
        return jsonify({"success":True,"error":response_db.get("error")})

@app.route('/api/logout', methods=['POST'])
async def logout():
    current_user = get_jwt_identity()  # Get user identity before clearing cookies
    response = await make_response(jsonify({"message": "Logout successful"}))
    unset_jwt_cookies(response)  # Clear access and refresh token cookies

    # Remove refresh token from store
    if current_user and current_user in refresh_token_store:
        del refresh_token_store[current_user]

    # Clear session
    async with session_lock:
        session.clear()

    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)