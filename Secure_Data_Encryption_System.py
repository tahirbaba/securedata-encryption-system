import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import re

# Generate encryption key
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data and attempt tracking
stored_data = {}
failed_attempts = 0
login_required = False

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    entry = stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hashed_passkey:
        failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        failed_attempts += 1
        return None

# Password strength checker
def check_password_strength(password):
    if len(password) < 8:
        return "Weak"
    elif re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"\d", password):
        return "Strong"
    else:
        return "Medium"

# --- Streamlit UI ---
st.set_page_config(page_title="Secure Data System", page_icon="🔐", layout="wide")
st.title("🔐 Secure Data Encryption System")

# --- Custom Style ---
st.markdown("""
    <style>
        .sidebar .sidebar-content {
            background-color: #f0f0f5;
            padding: 20px;
            border-radius: 10px;
        }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            border-radius: 5px;
            padding: 10px 20px;
            border: none;
            cursor: pointer;
            transition: 0.3s ease;
        }
        .stButton>button:hover {
            background-color: #45a049;
        }
        .stTextInput input {
            border-radius: 5px;
            padding: 10px;
            width: 100%;
        }
        .stTextArea textarea {
            border-radius: 5px;
            padding: 10px;
            width: 100%;
        }
        .stCode block {
            background-color: #2E2E2E;
            color: #fff;
            border-radius: 10px;
            padding: 15px;
            font-size: 16px;
        }
        .stAlert {
            background-color: #FFEB3B;
            color: #212121;
            padding: 10px;
            border-radius: 5px;
            font-weight: bold;
        }
        .stSuccess {
            background-color: #8BC34A;
            color: #fff;
            padding: 10px;
            border-radius: 5px;
        }
        .stError {
            background-color: #F44336;
            color: #fff;
            padding: 10px;
            border-radius: 5px;
        }
    </style>
""", unsafe_allow_html=True)

# --- Main Navigation ---
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📁 Menu", menu)

# Login check (using session state to manage login state)
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# Home Section
if choice == "Home":
    st.subheader("🏠 Welcome to Secure Data System")
    st.write("Store and retrieve encrypted data securely using your unique passkeys.")
    st.markdown(
        """
        <div style="background-color:#E8F5E9; border-radius:10px; padding:20px; margin-top:10px;">
            <h4 style="color:#388E3C; text-align:center;">🔒 **Your Data is Safe with Us**</h4>
            <p style="color:#388E3C; text-align:center;">With our encryption system, only you can access your data using your unique passkey. No one else can decrypt it!</p>
        </div>
        """, unsafe_allow_html=True)

# Store Data Section
elif choice == "Store Data":
    st.subheader("📝 Store New Data Securely")
    user_data = st.text_area("Enter your secret data:")
    passkey = st.text_input("Set your passkey:", type="password")

    # Password Strength Checker
    if passkey:
        strength = check_password_strength(passkey)
        st.markdown(f"**Password Strength**: {strength}")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and saved successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please enter both data and passkey.")

# Retrieve Data Section
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Stored Data")

    if failed_attempts >= 3:
        st.warning("🔐 Too many failed attempts! Please re-login.")
        st.stop()

    encrypted_input = st.text_area("Paste your encrypted data:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("✅ Decrypted Data:")
                st.code(result, language="text")
            else:
                st.error(f"❌ Incorrect passkey! Attempts left: {3 - failed_attempts}")
        else:
            st.error("⚠️ Both fields are required.")

# Login Section
elif choice == "Login":
    st.subheader("🔑 Login to Access Data")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Simple login for now
            st.session_state.logged_in = True
            failed_attempts = 0
            st.success("✅ Reauthorized! Go back to Retrieve Data.")
        else:
            st.error("❌ Wrong password.")

# Logout Section
if st.session_state.logged_in:
    logout_button = st.sidebar.button("Logout")
    if logout_button:
        st.session_state.logged_in = False
        st.success("You have been logged out!")
        st.experimental_rerun()
