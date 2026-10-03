from flask import Flask, render_template, request, redirect, url_for, session
import mysql.connector
from dotenv import load_dotenv
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
from markupsafe import escape


# Load environment variables
load_dotenv()


app = Flask(__name__)


# Flask session secret
flask_secret_key = os.getenv("FLASK_SECRET_KEY")

if not flask_secret_key:
    raise RuntimeError("FLASK_SECRET_KEY is missing from .env")

app.secret_key = flask_secret_key


# Session security settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# Load AES-256 encryption key
encryption_key_value = os.getenv("ENCRYPTION_KEY")

if not encryption_key_value:
    raise RuntimeError("ENCRYPTION_KEY is missing from .env")

encryption_key = bytes.fromhex(encryption_key_value)

if len(encryption_key) != 32:
    raise RuntimeError("ENCRYPTION_KEY must be 32 bytes for AES-256")


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )


# --------------------------------------------------
# AES-256-GCM ENCRYPTION
# --------------------------------------------------

def encrypt_data(data):
    aes = AESGCM(encryption_key)

    # Generate a unique 12-byte nonce
    nonce = os.urandom(12)

    encrypted_data = aes.encrypt(
        nonce,
        data.encode(),
        None
    )

    # Store nonce + encrypted data together
    return base64.b64encode(
        nonce + encrypted_data
    ).decode()


def decrypt_data(encrypted_data):
    aes = AESGCM(encryption_key)

    decoded_data = base64.b64decode(encrypted_data)

    nonce = decoded_data[:12]
    ciphertext = decoded_data[12:]

    decrypted_data = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    return decrypted_data.decode()


# --------------------------------------------------
# INPUT VALIDATION
# --------------------------------------------------

def validate_registration(username, email, password, secret_data):

    # Username
    if not re.fullmatch(r"[A-Za-z0-9_]{3,50}", username):
        return "Username must be 3-50 characters and contain only letters, numbers, and underscores."

    # Email
    if not re.fullmatch(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        email
    ):
        return "Please enter a valid email address."

    # Password
    if len(password) < 8 or len(password) > 128:
        return "Password must be between 8 and 128 characters."

    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."

    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."

    if not re.search(r"\d", password):
        return "Password must contain at least one number."

    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one special character."

    # Secret data
    if not secret_data.strip():
        return "Secret data cannot be empty."

    if len(secret_data) > 5000:
        return "Secret data must be 5000 characters or less."

    return None


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("register.html")


# --------------------------------------------------
# REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["POST"])
def register():

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    secret_data = request.form.get("secret_data", "")

    # Server-side validation
    validation_error = validate_registration(
        username,
        email,
        password,
        secret_data
    )

    if validation_error:
        return validation_error, 400

    # Hash password
    password_hash = generate_password_hash(password)

    # Encrypt sensitive data
    encrypted_secret = encrypt_data(secret_data)

    connection = None
    cursor = None

    try:

        connection = get_db_connection()
        cursor = connection.cursor()

        # Parameterized SQL query
        query = """
            INSERT INTO users
            (username, email, password_hash, secret_data)
            VALUES (%s, %s, %s, %s)
        """

        cursor.execute(
            query,
            (
                username,
                email,
                password_hash,
                encrypted_secret
            )
        )

        connection.commit()

        return "Registration successful! <a href='/login'>Login here</a>"

    except mysql.connector.Error as error:

        # Duplicate username or email
        if error.errno == 1062:
            return "Username or email already exists.", 409

        return "Registration failed. Please try again.", 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        return "Username and password are required.", 400

    if len(username) > 50:
        return "Invalid username or password.", 401

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        # Parameterized SQL query
        query = """
            SELECT id, username, password_hash
            FROM users
            WHERE username = %s
        """

        cursor.execute(
            query,
            (username,)
        )

        user = cursor.fetchone()

        # Verify password
        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(url_for("secret"))

        # Generic message prevents username enumeration
        return "Invalid username or password.", 401

    except mysql.connector.Error:

        return "Login failed. Please try again.", 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# --------------------------------------------------
# PROTECTED SECRET PAGE
# --------------------------------------------------

@app.route("/secret")
def secret():

    # Check whether user is logged in
    if "user_id" not in session:
        return "Please login first. <a href='/login'>Login</a>", 401

    connection = None
    cursor = None

    try:

        connection = get_db_connection()

        cursor = connection.cursor(
            dictionary=True
        )

        # Parameterized SQL query
        query = """
            SELECT username, secret_data
            FROM users
            WHERE id = %s
        """

        cursor.execute(
            query,
            (session["user_id"],)
        )

        user = cursor.fetchone()

        if not user:
            return "User not found.", 404

        # Decrypt secret data
        decrypted_secret = decrypt_data(
            user["secret_data"]
        )

        # Escape output to reduce XSS risk
        safe_username = escape(user["username"])
        safe_secret = escape(decrypted_secret)

        return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Secret Data</title>
            </head>

            <body>

                <h1>Secret Data</h1>

                <p>Welcome, {safe_username}!</p>

                <p>Your decrypted secret:</p>

                <strong>{safe_secret}</strong>

                <br><br>

                <a href="/logout">Logout</a>

            </body>
            </html>
        """

    except Exception:

        return "Unable to retrieve secret data.", 500

    finally:

        if cursor:
            cursor.close()

        if connection:
            connection.close()


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return "Logged out successfully. <a href='/login'>Login again</a>"


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    app.run(debug=False)
