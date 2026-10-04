import streamlit as st
import re
import secrets
import string
import sqlite3
import hashlib
from zxcvbn import zxcvbn


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔐",
    layout="centered"
)


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

DATABASE = "password_history.db"


def init_database():
    """
    Creates the SQLite database and password history table.
    Only password hashes and salts are stored.
    """

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


# Initialize database
init_database()


# =========================================================
# PASSWORD HASHING
# =========================================================

def hash_password(password, salt=None):
    """
    Creates a secure PBKDF2-HMAC-SHA256 hash.

    The actual password is never stored.
    """

    if salt is None:
        salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000
    )

    return password_hash.hex(), salt.hex()


def verify_password(password, stored_hash, stored_salt):
    """
    Verifies a password against a stored PBKDF2 hash.
    """

    salt = bytes.fromhex(stored_salt)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000
    ).hex()

    return secrets.compare_digest(
        password_hash,
        stored_hash
    )


# =========================================================
# PASSWORD REUSE CHECK
# =========================================================

def is_password_reused(password):
    """
    Checks whether the entered password matches
    any previously stored password hash.
    """

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        "SELECT password_hash, salt FROM password_history"
    )

    records = cursor.fetchall()

    connection.close()

    for stored_hash, stored_salt in records:

        if verify_password(
            password,
            stored_hash,
            stored_salt
        ):
            return True

    return False


# =========================================================
# SAVE PASSWORD HASH
# =========================================================

def save_password_hash(password):
    """
    Stores only the salted password hash.
    The original password is never stored.
    """

    password_hash, salt = hash_password(password)

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO password_history
        (password_hash, salt)
        VALUES (?, ?)
        """,
        (password_hash, salt)
    )

    connection.commit()
    connection.close()


# =========================================================
# STRONG PASSWORD GENERATOR
# =========================================================

def generate_strong_password(length=16):

    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    numbers = string.digits
    special = "!@#$%^&*"

    # Guarantee at least one character
    # from every required category.

    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(numbers),
        secrets.choice(special)
    ]

    all_characters = (
        uppercase +
        lowercase +
        numbers +
        special
    )

    for _ in range(length - 4):

        password.append(
            secrets.choice(all_characters)
        )

    # Securely shuffle password characters
    secrets.SystemRandom().shuffle(password)

    return "".join(password)


# =========================================================
# APPLICATION HEADER
# =========================================================

st.title("🔐 Password Strength Analyzer")

st.write(
    "Cybersecurity Internship Project - Thiranex"
)

st.info(
    "This tool evaluates password strength, "
    "provides security recommendations, generates "
    "strong passwords, and checks password reuse."
)


# =========================================================
# PASSWORD INPUT
# =========================================================

password = st.text_input(
    "Enter your password:",
    type="password",
    placeholder="Enter password for analysis..."
)


# =========================================================
# PASSWORD ANALYSIS
# =========================================================

if password:

    # -----------------------------------------------------
    # BASIC CHARACTER ANALYSIS
    # -----------------------------------------------------

    length = len(password)

    has_uppercase = bool(
        re.search(r"[A-Z]", password)
    )

    has_lowercase = bool(
        re.search(r"[a-z]", password)
    )

    has_number = bool(
        re.search(r"[0-9]", password)
    )

    has_special = bool(
        re.search(r"[^A-Za-z0-9]", password)
    )


    # -----------------------------------------------------
    # ZXCVBN ANALYSIS
    # -----------------------------------------------------

    result = zxcvbn(password)

    zxcvbn_score = result["score"]

    crack_time = result[
        "crack_times_display"
    ][
        "offline_slow_hashing_1e4_per_second"
    ]


    # Convert 0-4 score into 0-100
    score = zxcvbn_score * 25


    strength_levels = {
        0: "Very Weak",
        1: "Weak",
        2: "Moderate",
        3: "Strong",
        4: "Very Strong"
    }

    strength = strength_levels[
        zxcvbn_score
    ]


    # =====================================================
    # PASSWORD ANALYSIS DISPLAY
    # =====================================================

    st.subheader("📊 Password Analysis")

    st.write(
        f"**Password Length:** {length} characters"
    )


    # -----------------------------------------------------
    # LENGTH
    # -----------------------------------------------------

    if length >= 12:

        st.success(
            "✓ Good password length"
        )

    elif length >= 8:

        st.warning(
            "⚠ Password is acceptable, "
            "but 12+ characters are recommended"
        )

    else:

        st.error(
            "✗ Password is too short"
        )


    # -----------------------------------------------------
    # UPPERCASE
    # -----------------------------------------------------

    if has_uppercase:

        st.success(
            "✓ Contains uppercase letter"
        )

    else:

        st.error(
            "✗ Missing uppercase letter"
        )


    # -----------------------------------------------------
    # LOWERCASE
    # -----------------------------------------------------

    if has_lowercase:

        st.success(
            "✓ Contains lowercase letter"
        )

    else:

        st.error(
            "✗ Missing lowercase letter"
        )


    # -----------------------------------------------------
    # NUMBER
    # -----------------------------------------------------

    if has_number:

        st.success(
            "✓ Contains number"
        )

    else:

        st.error(
            "✗ Missing number"
        )


    # -----------------------------------------------------
    # SPECIAL CHARACTER
    # -----------------------------------------------------

    if has_special:

        st.success(
            "✓ Contains special character"
        )

    else:

        st.error(
            "✗ Missing special character"
        )


    # =====================================================
    # STRENGTH SCORE
    # =====================================================

    st.subheader("🔐 Password Strength")

    st.progress(
        score / 100
    )

    st.write(
        f"### Score: {score}/100"
    )


    if zxcvbn_score == 0:

        st.error(
            "🔴 Very Weak Password"
        )

    elif zxcvbn_score == 1:

        st.warning(
            "🟠 Weak Password"
        )

    elif zxcvbn_score == 2:

        st.warning(
            "🟡 Moderate Password"
        )

    elif zxcvbn_score == 3:

        st.success(
            "🟢 Strong Password"
        )

    else:

        st.success(
            "🔒 Very Strong Password"
        )


    # =====================================================
    # CRACK TIME
    # =====================================================

    st.subheader("⏱ Estimated Crack Time")

    st.info(
        f"Estimated offline cracking time: "
        f"**{crack_time}**"
    )


    # =====================================================
    # SECURITY SUGGESTIONS
    # =====================================================

    st.subheader("💡 Security Suggestions")

    feedback = result["feedback"]


    if feedback["warning"]:

        st.warning(
            f"⚠ {feedback['warning']}"
        )


    if feedback["suggestions"]:

        for suggestion in feedback["suggestions"]:

            st.write(
                f"• {suggestion}"
            )


    if length < 12:

        st.write(
            "• Use at least 12 characters."
        )


    if not has_uppercase:

        st.write(
            "• Add uppercase letters."
        )


    if not has_lowercase:

        st.write(
            "• Add lowercase letters."
        )


    if not has_number:

        st.write(
            "• Add numbers."
        )


    if not has_special:

        st.write(
            "• Add special characters."
        )


    # =====================================================
    # PASSWORD REUSE CHECK
    # =====================================================

    st.divider()

    st.subheader(
        "🔄 Password Reuse Detection"
    )

    st.write(
        "Check whether this password has "
        "already been used in this application's "
        "password history."
    )


    if st.button(
        "Check Password Reuse"
    ):

        if is_password_reused(password):

            st.error(
                "⚠ This password has been used before. "
                "Choose a different password."
            )

        else:

            st.success(
                "✓ This password has not been used before."
            )


            save_password_hash(password)

            st.info(
                "Only a salted password hash has been "
                "stored. The original password is not stored."
            )


# =========================================================
# STRONG PASSWORD GENERATOR
# =========================================================

st.divider()

st.subheader(
    "🚀 Generate a Strong Password"
)

st.write(
    "Generate a cryptographically secure random password."
)


if st.button(
    "Generate Strong Password"
):

    generated_password = generate_strong_password(
        16
    )

    st.code(
        generated_password,
        language=None
    )

    st.success(
        "Strong password generated successfully!"
    )

    st.caption(
        "Tip: Do not reuse the same password "
        "across multiple accounts."
    )


# =========================================================
# SECURITY INFORMATION
# =========================================================

st.divider()

st.subheader(
    "🛡️ Security Information"
)

st.write(
    """
    **Privacy:** Passwords entered into this application
    are not stored in plaintext. Password reuse detection
    stores only salted PBKDF2-HMAC-SHA256 password hashes.

    **Recommendation:** Use a unique password for every
    account and consider using a reputable password manager.
    """
)