
import streamlit as st
import hashlib
from cryptography.fernet import Fernet
from typing import Optional


st.set_page_config(page_title="Secure Data System", layout="centered")


if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = True

# Generate single Fernet key .
KEY = Fernet.generate_key()
cipher = Fernet(KEY)


stored_data = {} 


def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text: str) -> str:
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> Optional[str]:
    hashed_passkey = hash_passkey(passkey)
    for key, entry in stored_data.items():
        if entry["encrypted_text"] == encrypted_text and entry["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None


st.title("🛡️ Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("📁 Menu", menu)


if choice == "Home":
    st.subheader("🏠 Welcome to Secure Data System")
    st.markdown("""
        - 🔐 Encrypt and store your sensitive data.
        - 🔓 Retrieve it using your secret passkey.
        - 🔁 Login is required after 3 failed attempts.
        - 📌 All data is stored **temporarily in memory** (demo).
    """)


elif choice == "Store Data":
    st.subheader("📂 Store Data")

    label = st.text_input("Enter a Label for your Data (e.g. note1):")
    data = st.text_area("Enter the Text You Want to Encrypt:")
    passkey = st.text_input("Create a Secret Passkey:", type="password")

    if st.button("Encrypt & Store"):
        if label and data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(data)
            stored_data[label] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please fill in all fields.")

elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🚫 Too many failed attempts. Please login again.")
        st.stop()

    st.subheader("🔍 Retrieve Encrypted Data")

    encrypted_input = st.text_area("Paste the Encrypted Text:")
    passkey_input = st.text_input("Enter Your Secret Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("🔓 Decrypted Text:")
                st.code(result, language="text")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please enter both fields.")


elif choice == "Login":
    st.subheader("🔐 Reauthorization Required")
    master_password = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_password == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Login successful! You can now access Retrieve Data.")
        else:
            st.error("❌ Incorrect master password.")
