from quart import Quart, request, jsonify, make_response
from quart_jwt_extended import JWTManager, create_access_token
from quart_cors import cors
import aiohttp
from DBQuery import Database, handle_delete_account,handle_find_one,handle_reset_password_db, handle_register_db, handle_login_db, handle_save_email_account, handle_get_user_info, handle_update_info_user, handle_get_account_info
from datetime import timedelta, datetime
import os
from dotenv import load_dotenv
import aiosmtplib
import random
import string
import firebase_admin
from firebase_admin import credentials, messaging, storage
import uuid
import redis.asyncio as redis
import json
import time
import logging
import asyncio
import socketio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Initialize Quart app
app = Quart(__name__)
app = cors(app, allow_origin="*")
db = Database()

# Initialize SocketIO (async)
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins='*', engineio_path='/engine.io/')# Adauga handler pentru conexiune
import logging
logging.getLogger('socketio').setLevel(logging.DEBUG)
logging.getLogger('engineio').setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)

@sio.on('connect')
async def connect(sid, environ):
    logger.debug(f"Client connect attempt: sid={sid}, environ={environ}")
    print(f"Client connected: {sid}")
    await sio.emit('connected', {'message': 'Connected successfully'}, room=sid)
# Monta SocketIO pe aplica?ia ASGI

redis_client = redis.Redis(host='redis', port=6379, db=0) 

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('server.log')
    ]
)
logger = logging.getLogger(__name__)

# Verification code storage
verification_codes = {}
connected_users = {}
data_lock = asyncio.Lock()
reset_codes = {}

# Verification code expiration time
CODE_EXPIRATION_MINUTES = 15

# JWT Configuration
app.config['JWT_SECRET_KEY'] = 'AuthenticatorCryptMailSomeSecret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

# Load environment variables
load_dotenv()
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
WEB_SERVER_PORT = os.getenv("WEB_SERVER_PORT")
WEB_SERVER_IP = os.getenv("WEB_SERVER_IP")

WEB_BACKEND_URL = f"http://{WEB_SERVER_IP}:{WEB_SERVER_PORT}/api/data-from-mobile"

# SocketIO Handlers (adapted for async)

@sio.on('register')
async def handle_register(sid, data):
    email = data.get('email')
    if email:
        async with data_lock:
            connected_users.setdefault(email, set()).add(sid)
        logger.debug(f"Registered {email} to session {sid}")
        await sio.emit('registered', {'status': 'registered', 'email': email, 'sid': sid}, to=sid)
    else:
        logger.warning(f"Invalid register message: missing email")
        await sio.emit('error', {'status': 'error', 'message': 'Email required'}, to=sid)

@sio.event
async def disconnect(sid):
    async with data_lock:
        for email, sids in list(connected_users.items()):
            if sid in sids:
                sids.remove(sid)
                logger.debug(f"{email} disconnected from session {sid}")
                if not sids:
                    del connected_users[email]
                break

@sio.on('ping')
async def handle_ping(sid):
    logger.debug(f"Ping from sid={sid}")
    await sio.emit('pong', {'action': 'pong'}, to=sid)

# HTTP Routes (unchanged except for send_data_to_user)
@app.route('/test', methods=['GET'])
async def test():
    logger.debug("Test route accessed")
    return jsonify({"message": "Server is running", "timestamp": datetime.now().isoformat()}), 200

@app.route('/send-to-web', methods=['POST'])
async def get_register_details():
    data = await request.get_json()
    email = data.get('email')
    owner_email = data.get('ownerEmail')
    action = data.get('action')
    public_key = data.get('publicKey')

    if not email or not public_key or not action or not owner_email:
        logger.error("Missing required fields in /send-to-web")
        return make_response(jsonify({'message': 'Email and public key are required'}), 400)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(WEB_BACKEND_URL, json=data) as response:
                if response.status == 200:
                    response_data = await response.json()
                    logger.debug(f"Forwarded data to {WEB_BACKEND_URL}: {response_data}")
                    return jsonify({"success": True})
                else:
                    logger.error(f"Failed to forward data: {await response.text()}")
                    return jsonify({
                        "success": False,
                        "message": "Failed to forward data",
                        "error": await response.text()
                    }), response.status
    except Exception as e:
        logger.error(f"Error in /send-to-web: {e}")
        return jsonify({"success": False, "message": "An error occurred", "error": str(e)}), 500


# Add this new route to your app.py file

@app.route('/delete-user', methods=['DELETE']) # Using DELETE method is conventional for deletion
async def delete_user_endpoint():
    # It's good practice to secure this endpoint, e.g., with JWT authentication
    # to ensure only authorized users/admins can delete accounts.
    # For simplicity, this example assumes an authorized request.

    data = await request.get_json()
    email_to_delete = data

    if not email_to_delete:
        logger.error("Missing 'email' for user deletion request")
        return jsonify({"success": False, "message": "Email to delete is required"}), 400

    try:
        # Call the existing handle_delete_account function from DBQuery.py
        # You'll need to pass 'db' and the email
        delete_result = await handle_delete_account(db, email_to_delete)

        if delete_result["success"]:
            logger.debug(f"User {email_to_delete} deleted successfully.")
            return jsonify({
                "success": True,
                "message": f"User {email_to_delete} deleted successfully."
            }), 200
        else:
            logger.error(f"Failed to delete user {email_to_delete}: {delete_result.get('message', 'Unknown error')}")
            return jsonify({
                "success": False,
                "message": delete_result.get("message", "Failed to delete user.")
            }), 400 # Or 500 if it's a server-side error during deletion

    except Exception as e:
        logger.error(f"Error during user deletion for {email_to_delete}: {e}")
        return jsonify({
            "success": False,
            "message": "An unexpected error occurred during user deletion.",
            "error": str(e)
        }), 500

@app.route('/register', methods=['POST'])
async def handle_register():
    data = await request.get_json()

    # Log received data for debugging
    print(f"Received data from request: {data}")

    email = data.get("email")
    password = data.get("password")
    fullName = data.get("fullName")
    gender = data.get("gender")
    birthday = data.get("birthday")
    phone = data.get("phone")
    tokenDevice = data.get("tokenDevice")

    if not all([email, password, fullName, gender, birthday, phone, tokenDevice]):
        logger.error("Missing required fields in /register")
        return jsonify({
            "success": False,
            "message": "All fields are required",
            "verificationRequired": False,
            "authToken": None
        }), 400

    print("AM AJUNS PANA AICI!!! (After input validation)") # Debugging print

    try:
        # First, attempt to register the user in the database
        payload = {
            "email": email,
            "password": password,
            "fullName": fullName,
            "gender": gender,
            "birthday": birthday,
            "phone": phone,
            "tokenDevice": tokenDevice,
        }

        response_db = await handle_register_db(db, payload)
        print(f"Response from handle_register_db: {response_db}") # Log DB response

        if response_db["success"]:
            logger.debug(f"User registered successfully in DB: {email}")

            # Database registration successful, now send verification email
            try:
                code = ''.join(random.choices(string.digits, k=6))
                expires_at = datetime.now() + timedelta(minutes=CODE_EXPIRATION_MINUTES)
                verification_codes[email] = {"code": code, "expires_at": expires_at}

                subject = "Your Verification Code"
                body = f"Your verification code is: {code}\nThis code will expire in {CODE_EXPIRATION_MINUTES} minutes."
                message = f"Subject: {subject}\n\n{body}"

                await aiosmtplib.send(
                    message,
                    hostname=SMTP_SERVER,
                    port=SMTP_PORT,
                    username=EMAIL_ADDRESS,
                    password=EMAIL_PASSWORD,
                    use_tls=True, # Ensure use_tls is True if your SMTP server requires it
                    sender=EMAIL_ADDRESS,
                    recipients=[email]
                )
                logger.debug(f"Verification email sent to {email}")

                return jsonify({
                    "success": True,
                    "message": "Registration successful. Verification email sent! Please check your email.",
                    "verificationRequired": True,
                    "authToken": None
                }), 201 # 201 Created

            except Exception as email_e:
                logger.error(f"Error sending verification email to {email}: {str(email_e)}")
                # If email sending fails, you might still consider the user registered in DB but
                # need to handle the verification flow differently or inform the user.
                return jsonify({
                    "success": False,
                    "message": "Registration successful, but failed to send verification email.",
                    "verificationRequired": True, # Still requires verification if email didn't go
                    "authToken": None,
                    "error": str(email_e)
                }), 500 # Internal Server Error for email sending issue
        else:
            # Database registration failed
            logger.error(f"Registration error from DB: {response_db.get('message', 'Unknown DB error')}")
            return jsonify({
                "success": False,
                "message": response_db.get("message", "Registration failed due to a database error."),
                "verificationRequired": False,
                "authToken": None
            }), 400 # Or 500 if it's an unexpected DB error

    except Exception as e:
        logger.error(f"An unexpected error occurred during registration for {email}: {e}")
        return jsonify({
            "success": False,
            "message": "An unexpected error occurred during registration.",
            "verificationRequired": False,
            "authToken": None,
            "error": str(e)
        }), 500
@app.route('/login', methods=['POST'])
async def handle_login():
    data = await request.get_json()
    email = data.get("email")
    password = data.get("password")
    tokenDevice = data.get("tokenDevice")

    payload = {
        "email": email,
        "password": password,
        "tokenDevice": tokenDevice
    }
    response_db = await handle_login_db(db, payload)

    if response_db["success"]:
        access_token = create_access_token(identity=email)
        logger.debug(f"Login successful: {email}")
        return jsonify({
            "success": True,
            "message": "Login successful",
            "authToken": access_token
        }), 200
    else:
        logger.error(f"Login failed: {response_db['message']}")
        return jsonify({
            "success": False,
            "message": response_db["message"],
            "authToken": None
        }), 401

@app.route('/verify-email', methods=['POST'])
async def verify_email():
    data = await request.get_json()
    email = data.get("email")
    code = data.get("verificationCode")

    if not email or not code:
        logger.error("Email or code not provided")
        return jsonify({
            "success": False,
            "message": "Email and verification code are required"
        }), 400

    if email not in verification_codes:
        logger.error("No verification requested for this email")
        return jsonify({
            "success": False,
            "message": "No verification requested for this email or code expired"
        }), 400

    stored_code = verification_codes[email]

    if datetime.now() > stored_code["expires_at"]:
        del verification_codes[email]
        logger.error("Verification code expired")
        return jsonify({
            "success": False,
            "message": "Verification code has expired"
        }), 400

    if code != stored_code["code"]:
        logger.error("Invalid verification code")
        return jsonify({
            "success": False,
            "message": "Invalid verification code"
        }), 400

    try:
        del verification_codes[email]
        access_token = create_access_token(identity=email)
        logger.debug(f"Email verified: {email}")
        return jsonify({
            "success": True,
            "message": "Email verified successfully",
            "authToken": access_token
        }), 200
    except Exception as e:
        logger.error(f"Database error: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An error occurred during verification",
            "error": str(e)
        }), 500
        
@app.route('/forgot-password', methods=['POST'])
async def forgot_password():
    data = await request.get_json()
    email = data.get("email")

    if not email:
        logger.error("Email not provided")
        return jsonify({
            "success": False,
            "message": "Email is required"
        }), 400

    import re
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        logger.error("Invalid email format")
        return jsonify({
            "success": False,
            "message": "Invalid email format"
        }), 400


    payload={
        "email": email
    }
    user = await handle_find_one(db,payload)  # Adjust for your DB
    if not user:
        logger.debug(f"No user found for email: {email}")
        return jsonify({
            "success": False,
            "message": "Your email does not exist in our database",
            "emailSent": False
        }), 500

    if email in reset_codes and datetime.now() < reset_codes[email]["expires_at"]:
        logger.warning(f"Reset request too soon for email: {email}")
        return jsonify({
            "success": False,
            "message": "Please wait before requesting another code"
        }), 429

    # Generate a 6-digit numeric code
    verification_code = ''.join(random.choices(string.digits, k=6))
    expires_at = datetime.now() + timedelta(minutes=10)  # Code valid for 10 minutes

    reset_codes[email] = {
        "code": verification_code,
        "expires_at": expires_at
    }
    
    try:
        subject = "Password Reset Verification Code"
        body = f"""
        Hello,

        Your verification code for password reset is: {verification_code}

        This code will expire in 10 minutes. If you did not request this, please ignore this email.

        Regards,
        Your CryptMail Team
        """

        message = f"Subject: {subject}\n\n{body}"
        await aiosmtplib.send(
                message,
                hostname=SMTP_SERVER,
                port=SMTP_PORT,
                username=EMAIL_ADDRESS,
                password=EMAIL_PASSWORD,
                use_tls=True,
                sender=EMAIL_ADDRESS,
                recipients=[email]
            )
        logger.debug(f"Verification email sent to {email}")
        return jsonify({
            "success": True,
            "message": "If the email exists, a verification code has been sent",
            "emailSent": True
        }), 200

    except Exception as e:
        logger.error(f"Failed to send verification code: {str(e)}")
        if email in reset_codes:
            del reset_codes[email]
        return jsonify({
            "success": False,
            "message": "Failed to send verification code",
            "error": str(e)
        }), 500
        
@app.route('/delete-account', methods=['POST'])
async def delete_account():
    data = await request.get_json()
    email = data

    if not email:
        logger.error("Email not provided")
        return jsonify({
            "success": False,
            "message": "Email is required"
        }), 400

    try:
        payload = {
            "email": email
        }
        response_db = await handle_delete_account(db, payload)  # Adjust for your DB

        if response_db["success"]:
            logger.debug(f"Account deleted: {email}")
            return jsonify({
                "success": True,
                "message": "Account deleted successfully"
            }), 200
        else:
            logger.error(f"Account deletion failed: {response_db['message']}")
            return jsonify({
                "success": False,
                "message": response_db["message"]
            }), 400
    except Exception as e:
        logger.error(f"Error deleting account: {e}")
        return jsonify({
            "success": False,
            "message": "An error occurred",
            "error": str(e)
        }), 500
        
        
@app.route('/verify-reset-code', methods=['POST'])
async def verify_reset_code():
    data = await request.get_json()
    email = data.get("email")
    code = data.get("code")

    if not email or not code:
        logger.error("Email or code not provided")
        return jsonify({
            "success": False,
            "message": "Email and verification code are required"
        }), 400

    if email not in reset_codes:
        logger.error("No reset code for this email")
        return jsonify({
            "success": False,
            "message": "No reset code requested for this email or code expired"
        }), 400

    stored_code = reset_codes[email]

    if datetime.now() > stored_code["expires_at"]:
        del reset_codes[email]
        logger.error("Verification code expired")
        return jsonify({
            "success": False,
            "message": "Verification code has expired"
        }), 400

    if code != stored_code["code"]:
        logger.error("Invalid verification code")
        return jsonify({
            "success": False,
            "message": "Invalid verification code"
        }), 400

    try:
        # Keep the code valid until password reset (or set a new timeout)
        logger.debug(f"Reset code verified for: {email}")
        return jsonify({
            "success": True,
            "message": "Verification code is valid"
        }), 200
    except Exception as e:
        logger.error(f"Error during code verification: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An error occurred during verification",
            "error": str(e)
        }), 500
        
@app.route('/reset-password', methods=['POST'])
async def reset_password():
    data = await request.get_json()
    email = data.get("email")
    new_password = data.get("newPassword")

    if not email or not new_password:
        logger.error("Email or new password not provided")
        return jsonify({
            "success": False,
            "message": "Email and new password are required"
        }), 400

    if email not in reset_codes:
        logger.error("No verified reset code for this email")
        return jsonify({
            "success": False,
            "message": "No valid reset code for this email or session expired"
        }), 400

    try:
        # Update the password in the database
        payload = {
            "email": email,
            "newPassword": new_password
        }
        response_db = await handle_reset_password_db(db, payload)  # Adjust for your DB
        if response_db["success"]:
            logger.debug(f"Password reset successfully for: {email}")
            del reset_codes[email]
            return jsonify({
                "success": True,
                "message": "Password reset successfully"
            }), 200
        else:
            logger.error(f"Password reset failed: {response_db['message']}")
            return jsonify({
                "success": False,
                "message": response_db["message"]
            }), 400
    except Exception as e:
        logger.error(f"Database error during password reset: {str(e)}")
        return jsonify({
            "success": False,
            "message": "An error occurred during password reset",
            "error": str(e)
        }), 500

@app.route('/resend-verification', methods=['POST'])
async def resend_verification():
    data = await request.get_json()
    email = data.get("email")

    if not email:
        logger.error("Email is required")
        return jsonify({
            "success": False,
            "message": "Email is required"
        }), 400

    try:
        code = ''.join(random.choices(string.digits, k=6))
        expires_at = datetime.now() + timedelta(minutes=CODE_EXPIRATION_MINUTES)
        verification_codes[email] = {"code": code, "expires_at": expires_at}

        subject = "Your New Verification Code"
        body = f"Your new verification code is: {code}\nThis code will expire in {CODE_EXPIRATION_MINUTES} minutes."
        message = f"Subject: {subject}\n\n{body}"

        try:
            await aiosmtplib.send(
                message,
                hostname=SMTP_SERVER,
                port=SMTP_PORT,
                username=EMAIL_ADDRESS,
                password=EMAIL_PASSWORD,
                use_tls=True,
                sender=EMAIL_ADDRESS,
                recipients=[email]
            )
            logger.debug(f"Verification email resent to {email}")
            return jsonify({
                "success": True,
                "message": "New verification code sent"
            }), 200
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            return jsonify({
                "success": False,
                "message": "Failed to resend verification email"
            }), 500
    except Exception as e:
        logger.error(f"Error resending verification: {e}")
        return jsonify({
            "success": False,
            "message": "An error occurred",
            "error": str(e)
        }), 500

@app.route('/save-email-account', methods=['POST'])
async def save_email_account():
    data = await request.get_json()
    email = data.get("myemail")
    emailtobesaved = data.get("emailToBeSaved")

    if not email or not emailtobesaved:
        logger.error("Email and email to be saved are required")
        return jsonify({
            "success": False,
            "message": "Email and email to be saved are required"
        }), 400

    try:
        payload = {
            "email": email,
            "emailToBeSaved": emailtobesaved
        }
        response_db = await handle_save_email_account(db, payload)

        if response_db["success"]:
            logger.debug(f"Email saved: {emailtobesaved}")
            return jsonify({
                "success": True,
                "message": "Email saved successfully"
            }), 200
        else:
            logger.error(f"Error saving email: {response_db['message']}")
            return jsonify({
                "success": False,
                "message": response_db["message"]
            }), 400
    except Exception as e:
        logger.error(f"Error saving email account: {e}")
        return jsonify({
            "success": False,
            "message": "An error occurred",
            "error": str(e)
        }), 500

@app.route('/get-info-account', methods=['POST'])
async def get_account_info():
    data = await request.get_json()
    email = data  # Adjusted for expected input

    if not email:
        logger.error("Email is required")
        return jsonify({
            "success": False,
            "message": "Email is required"
        }), 400

    try:
        payload = {"email": email}
        response_db = await handle_get_user_info(db, payload)

        if response_db["success"]:
            logger.debug(f"Account info retrieved: {email}")
            return jsonify(response_db), 200
        else:
            logger.error("Failed to retrieve account info")
            return jsonify({
                "success": False,
            }), 400
    except Exception as e:
        logger.error(f"Error getting account info: {e}")
        return jsonify({
            "success": False,
            "message": "An error occurred",
            "error": str(e)
        }), 500

@app.route('/update-info-user', methods=['POST'])
async def update_info_user():
    data = await request.get_json()
    emailaddress = data.get("emailaddress")
    fullName = data.get("fullName")
    gender = data.get("gender")
    phoneNumber = data.get("phoneNumber")
    birthday = data.get("birthday")

    if not all([emailaddress, fullName, gender, phoneNumber, birthday]):
        logger.error("All fields are required")
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    try:
        payload = {
            "emailaddress": emailaddress,
            "fullName": fullName,
            "gender": gender,
            "phoneNumber": phoneNumber,
            "birthday": birthday
        }
        response_db = await handle_update_info_user(db, payload)

        if response_db["success"]:
            logger.debug(f"User info updated: {emailaddress}")
            return jsonify({"": "User info updated successfully"}), 200
        else:
            logger.error(f"Error updating user info: {response_db['message']}")
            return jsonify({"success": False, "message": response_db["message"]}), 400
    except Exception as e:
        logger.error(f"Error updating user info: {e}")
        return jsonify({
            "success": False,
            "message": "An error occurred",
            "error": str(e)
        }), 500

async def send_data_to_user(email, data):
    async with data_lock:
        sids = connected_users.get(email, set())
        if not sids:
            logger.warning(f"No connected sessions for email: {email}")
            return False

        success = False
        for sid in list(sids):
            try:
                logger.debug(f"Sending to {email} on session {sid}: {data}")
                await sio.emit('encrypted_data', data, to=sid)
                success = True
            except Exception as e:
                logger.error(f"Failed to send to {email} on session {sid}: {e}")
                sids.discard(sid)
                if not sids:
                    del connected_users[email]
        return success

@app.route('/receive-data', methods=['POST'])
async def receive_data():
    try:
        data = await request.get_json()
        if not data:
            logger.error("No JSON data received")
            return jsonify({"error": "No JSON data provided"}), 400

        email = data.get("email")
        signedHash = data.get("signedHash")
        encM = data.get("encM")
        c = data.get("c")

        if not all([email, signedHash, encM, c]):
            logger.error("Missing required fields")
            return jsonify({"error": "Missing required fields"}), 400

        request_id = str(uuid.uuid4())
        payload = {"email": email}
        logger.debug(f"Fetching account info for email: {email}")
        response_db = await handle_get_account_info(db, payload)

        if not response_db.get("success"):
            logger.error(f"Failed to fetch account info: {response_db.get('message')}")
            return jsonify({"error": response_db.get("message")}), 404

        state = {
            "signedHash": signedHash,
            "randomString": data.get("randomString"),
            "status": "pending",
            "encM": encM,
            "c": c,
            "email": email,
            "finalZPK": None,
            "success": None,
        }
        await redis_client.setex(f"zkp:{email}:{request_id}", 300, json.dumps(state))

        pairs = response_db.get("pairs")
        if not pairs:
            logger.error(f"No device tokens found for email: {email}")
            return jsonify({"error": "No device tokens found for the given email"}), 404

        sent = False
        for pair in pairs:
            target_email, _ = pair
            data_to_send = {
                "ownerEmail": target_email,
                "email": email,
                "signedHash": signedHash,
                "encM": encM,
                "c": c,
                "randomString": data.get("randomString"),
                "requestId": request_id
            }
            logger.debug(f"Attempting to send data to {target_email}: {data_to_send}")
            if await send_data_to_user(target_email, data_to_send):
                sent = True

        if not sent:
            logger.error("No data sent: no connected clients")
            return jsonify({"error": "No connected clients available to receive data"}), 503

        timeout = 30
        start_time = time.time()
        while time.time() - start_time < timeout:
            state_json = await redis_client.get(f"zkp:{email}:{request_id}")
            if state_json:
                state = json.loads(state_json)
                if state.get("status") == "verified":
                    logger.debug("ZKP verified")
                    return jsonify({
                        "message": "ZKP verified",
                        "success": state.get("success"),
                        "finalZPK": state.get("finalZPK")
                    }), 200
                elif state.get("status") == "failed":
                    logger.debug("ZKP verification failed")
                    return jsonify({
                        "message": "ZKP verification failed",
                        "success": False
                    }), 400
            await asyncio.sleep(0.5)

        logger.error("ZKP response timeout")
        return jsonify({"error": "ZKP response timeout"}), 504

    except Exception as e:
        logger.error(f"Error in receive_data: {e}")
        return jsonify({"error": "Failed to send data over WebSocket", "details": str(e)}), 500

@app.route('/send-zpk', methods=['POST'])
async def send_credentials():
    data = await request.get_json()
    finalZPK = data.get("finalZPK")
    ownerEmail = data.get("ownerEmail")
    email = data.get("email")
    requestId = data.get("requestId")

    if not all([email, ownerEmail, finalZPK, requestId]):
        logger.error("Missing required fields")
        return jsonify({"error": "Missing required fields"}), 400

    try:
        redis_key = f"zkp:{email}:{requestId}"
        state_json = await redis_client.get(redis_key)
        if not state_json:
            logger.error("Request ID not found")
            return jsonify({"error": "Request ID not found"}), 404

        state = json.loads(state_json)
        state["status"] = "verified"
        state["finalZPK"] = finalZPK
        state["success"] = True
        await redis_client.setex(redis_key, 300, json.dumps(state))

        logger.debug(f"ZKP stored for {email}")
        return jsonify({"success": True}), 200
    except Exception as e:
        logger.error(f"Error storing ZKP: {e}")
        return jsonify({"success": False, "message": "An error occurred", "error": str(e)}), 500

@app.route('/debug/connected-users', methods=['GET'])
async def debug_connected_users():
    logger.debug("Connected users requested")
    async with data_lock:
        return jsonify({"connected_users": {email: list(sids) for email, sids in connected_users.items()}})

socketio_app = socketio.ASGIApp(sio, app, socketio_path='/engine.io/') # <--- IMPORTANT CHANGE HERE

if __name__ == '__main__':
    import uvicorn
    # IMPORTANT: Ensure this is 'socketio_app', not 'app' directly
    # 'app' is the Quart application
    uvicorn.run(socketio_app, host="0.0.0.0", port=6000, ws="websockets")