from flask import Flask, render_template_string, request, redirect, session
import os
import io
import base64
import re
import traceback
import bcrypt
import pyotp
import qrcode
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "development-only-change-this"
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get(
        "COOKIE_SECURE", "false"
    ).lower() == "true",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800
)

# =====================================================
# DATABASE - SUPABASE POSTGRESQL
# =====================================================

DATABASE_URL = os.environ.get("DATABASE_URL")


class DatabaseConnection:
    """Small adapter that keeps the conn.execute() style."""

    def __init__(self):
        if not DATABASE_URL:
            raise RuntimeError(
                "DATABASE_URL is missing. Add your Supabase connection "
                "string in Render > Environment."
            )
        self.connection = psycopg2.connect(
            DATABASE_URL,
            sslmode="require",
            cursor_factory=RealDictCursor
        )

    def execute(self, query, params=()):
        cursor = self.connection.cursor()
        cursor.execute(query.replace("?", "%s"), params)
        return cursor

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


def get_db():
    return DatabaseConnection()


def create_database():
    conn = get_db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(30) UNIQUE NOT NULL,
                password_hash BYTEA NOT NULL,
                totp_secret TEXT NOT NULL,
                totp_enabled BOOLEAN NOT NULL DEFAULT FALSE
            )
        """)
        conn.commit()
    finally:
        conn.close()


create_database()


def get_user_by_id(user_id):
    conn = get_db()
    try:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
    finally:
        conn.close()


def clean_username(raw):
    """Trim, collapse extra spaces, lowercase."""
    return " ".join(raw.split()).lower()


# =====================================================
# ERROR HANDLER (shows the real error in Render > Logs)
# =====================================================

@app.errorhandler(Exception)
def handle_error(e):
    print("=== APP ERROR ===")
    print(traceback.format_exc())
    return (
        "<h2>Something went wrong.</h2>"
        "<p>Please go back and try again.</p>"
        '<a href="/">Home</a>',
        500
    )


# =====================================================
# COMMON DESIGN
# =====================================================

BASE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure 2FA Login System</title>

    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        * { box-sizing: border-box; }

        body {
            background: #101827;
            color: white;
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
        }

        .box {
            background: #1e293b;
            padding: 35px;
            border-radius: 16px;
            width: 100%;
            max-width: 420px;
            text-align: center;
            box-shadow: 0 10px 35px #0005;
        }

        h1 { color: #38bdf8; }

        input {
            width: 100%;
            padding: 14px;
            margin: 10px 0;
            border-radius: 8px;
            border: none;
            font-size: 15px;
        }

        button {
            width: 100%;
            padding: 13px;
            margin-top: 15px;
            background: #16a34a;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
        }

        button:hover { background: #15803d; }

        a { color: #38bdf8; }

        .error { color: #f87171; }

        .success { color: #4ade80; }

        img {
            max-width: 260px;
            width: 100%;
            background: white;
            padding: 10px;
            border-radius: 8px;
        }

        .links { margin-top: 20px; }
    </style>
</head>

<body>
    {{ content|safe }}
</body>
</html>
"""


def show_page(template, **kwargs):
    content = render_template_string(template, **kwargs)
    return render_template_string(BASE, content=content)


# =====================================================
# HOME PAGE
# =====================================================

HOME_PAGE = """
<div class="box">

    <h1>🔐 Secure Login System</h1>

    <p>Welcome to Multi-User Two-Factor Authentication</p>

    <a href="/signup">
        <button>Create New Account - Sign Up</button>
    </a>

    <a href="/login">
        <button>Existing User - Sign In</button>
    </a>

</div>
"""


@app.route("/")
def home():
    return show_page(HOME_PAGE)


# =====================================================
# SIGNUP
# =====================================================

SIGNUP_PAGE = """
<div class="box">

    <h1>Create Account</h1>

    <p>Register your own secure account.</p>

    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}

    <form method="POST">

        <input
            type="text"
            name="username"
            placeholder="Your Name"
            minlength="3"
            maxlength="30"
            required
        >

        <input
            type="password"
            name="password"
            placeholder="Create Password"
            required
        >

        <input
            type="password"
            name="confirm_password"
            placeholder="Confirm Password"
            required
        >

        <button type="submit">Sign Up</button>

    </form>

    <div class="links">
        Already have an account?
        <a href="/login">Sign In</a>
    </div>

</div>
"""


@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = clean_username(request.form.get("username", ""))
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Letters and single spaces only, 3-30 characters
        if not re.fullmatch(r"[a-z][a-z ]{2,29}", username):
            return show_page(
                SIGNUP_PAGE,
                error="Name must be 3-30 letters (spaces allowed)."
            )

        if password != confirm_password:
            return show_page(
                SIGNUP_PAGE,
                error="Passwords do not match."
            )

        if len(password) < 10 or len(password.encode("utf-8")) > 72:
            return show_page(
                SIGNUP_PAGE,
                error="Password must be at least 10 characters and at most 72 bytes."
            )

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        # Each user gets a different TOTP secret.
        secret = pyotp.random_base32()

        conn = get_db()

        try:
            cursor = conn.execute("""
                INSERT INTO users
                (username, password_hash, totp_secret)
                VALUES (?, ?, ?)
                RETURNING id
            """, (username, psycopg2.Binary(password_hash), secret))

            user_id = cursor.fetchone()["id"]
            conn.commit()

        except psycopg2.IntegrityError:
            conn.rollback()
            conn.close()

            return show_page(
                SIGNUP_PAGE,
                error="This name already exists. Choose another."
            )

        conn.close()

        session.clear()
        session["setup_user_id"] = user_id

        return redirect("/setup-2fa")

    return show_page(SIGNUP_PAGE, error=None)


# =====================================================
# GENERATE PERSONAL QR CODE
# =====================================================

def generate_qr(secret, username):

    totp = pyotp.TOTP(secret)

    uri = totp.provisioning_uri(
        name=username,
        issuer_name="Secure 2FA Login"
    )

    qr = qrcode.make(uri)

    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")

    return base64.b64encode(
        buffer.getvalue()
    ).decode("utf-8")


# =====================================================
# FIRST-TIME 2FA SETUP
# =====================================================

SETUP_PAGE = """
<div class="box">

    <h1>Setup Google Authenticator</h1>

    <p>Scan your personal QR code using Google Authenticator.</p>

    <img src="data:image/png;base64,{{ qr_code }}">

    <p>Enter the 6-digit code shown in your app.</p>

    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}

    <form method="POST">

        <input
            type="text"
            name="code"
            placeholder="6-digit code"
            maxlength="6"
            inputmode="numeric"
            required
        >

        <button type="submit">Verify and Activate</button>

    </form>

</div>
"""


@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():

    user_id = session.get("setup_user_id")

    if not user_id:
        return redirect("/signup")

    user = get_user_by_id(user_id)

    if not user:
        session.clear()
        return redirect("/signup")

    if request.method == "POST":

        code = request.form.get("code", "").strip()

        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code, valid_window=1):

            conn = get_db()

            try:
                conn.execute("""
                    UPDATE users
                    SET totp_enabled = TRUE
                    WHERE id = ?
                """, (user_id,))
                conn.commit()
            finally:
                conn.close()

            session.clear()
            session["authenticated"] = True
            session["user_id"] = user_id
            session["username"] = user["username"]

            return redirect("/dashboard")

        return show_page(
            SETUP_PAGE,
            qr_code=generate_qr(
                user["totp_secret"],
                user["username"]
            ),
            error="Invalid code. Please try again."
        )

    return show_page(
        SETUP_PAGE,
        qr_code=generate_qr(
            user["totp_secret"],
            user["username"]
        ),
        error=None
    )


# =====================================================
# SIGNIN
# =====================================================

LOGIN_PAGE = """
<div class="box">

    <h1>Sign In</h1>

    <p>Enter your registered account details.</p>

    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}

    <form method="POST">

        <input
            type="text"
            name="username"
            placeholder="Your Name"
            required
        >

        <input
            type="password"
            name="password"
            placeholder="Password"
            required
        >

        <button type="submit">Sign In</button>

    </form>

    <div class="links">
        New user?
        <a href="/signup">Create Account</a>
    </div>

</div>
"""


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = clean_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        conn = get_db()

        try:
            user = conn.execute("""
                SELECT * FROM users
                WHERE username = ?
            """, (username,)).fetchone()
        finally:
            conn.close()

        if not user or not bcrypt.checkpw(
            password.encode("utf-8"),
            bytes(user["password_hash"])
        ):
            return show_page(
                LOGIN_PAGE,
                error="Invalid name or password."
            )

        if not user["totp_enabled"]:
            session.clear()
            session["setup_user_id"] = user["id"]
            return redirect("/setup-2fa")

        session.clear()
        session["pending_user_id"] = user["id"]

        return redirect("/2fa")

    return show_page(LOGIN_PAGE, error=None)


# =====================================================
# LOGIN 2FA VERIFICATION
# =====================================================

TWO_FA_PAGE = """
<div class="box">

    <h1>Two-Factor Verification</h1>

    <p>Welcome, {{ username|title }}!</p>

    <p>Enter your Google Authenticator code.</p>

    {% if error %}
        <p class="error">{{ error }}</p>
    {% endif %}

    <form method="POST">

        <input
            type="text"
            name="code"
            placeholder="000000"
            maxlength="6"
            inputmode="numeric"
            required
        >

        <button type="submit">Verify Login</button>

    </form>

</div>
"""


@app.route("/2fa", methods=["GET", "POST"])
def two_fa():

    user_id = session.get("pending_user_id")

    if not user_id:
        return redirect("/login")

    user = get_user_by_id(user_id)

    if not user or not user["totp_enabled"]:
        session.clear()
        return redirect("/login")

    if request.method == "POST":

        code = request.form.get("code", "").strip()

        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code, valid_window=1):

            session.clear()

            session["authenticated"] = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect("/dashboard")

        return show_page(
            TWO_FA_PAGE,
            username=user["username"],
            error="Invalid authentication code."
        )

    return show_page(
        TWO_FA_PAGE,
        username=user["username"],
        error=None
    )


# =====================================================
# USER DASHBOARD
# =====================================================

DASHBOARD_PAGE = """
<div class="box">

    <h1 class="success">Login Successful!</h1>

    <h2>Welcome, {{ username|title }}!</h2>

    <p>Your account is securely authenticated.</p>

    <p>Name: {{ username|title }}</p>

    <p>Two-Factor Authentication: Enabled ✓</p>

    <a href="/logout">
        <button>Logout</button>
    </a>

</div>
"""


@app.route("/dashboard")
def dashboard():

    if not session.get("authenticated"):
        return redirect("/login")

    return show_page(
        DASHBOARD_PAGE,
        username=session["username"]
    )


# =====================================================
# LOGOUT
# =====================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# =====================================================
# RUN APPLICATION
# =====================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )