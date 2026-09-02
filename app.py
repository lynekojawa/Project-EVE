"""
Project EVE v2.1 - UI
"""

import collections
import string
import time
import altair as alt
import pandas as pd
import streamlit as st

from cipher_arsenal.cipher_engine import CryptoEngine
from database.db_manager import DBManager
from protocol_engine.protocol_engine import KDFEngine

st.set_page_config(page_title="Project EVE v2.1", layout="wide")
st.title("Project EVE v2.1")

#Session State Persistence
if "engine" not in st. session_state:
    st.session_state.engine = CryptoEngine()
if "db" not in st.session_state:
    st.session_staate.db = DBManager()

with st.sidebar:
    st.title("EVE Identity")

    st.warning("""
        ⚠️ **Cryptographic Protocol Demo (v2.1)**
        This is cryptographic protocol Demo, do not provide any personal information. 
        This messanger include the following:
        • 1536-bit Safe Prime MODP Key Exchange
        • Multi-Engine Cipher Arsenal (Z_256)
        • Shared-Secret Cipher Identification (SSCI)
        • HMAC-SHA256 & Anti-Replay Temporal Guard
    """)

    if "username" in st.session_state:
        st.success(f"Authenticated as **{st.session_state.username}**")
        if st.button("Switch User (Logout)", user_container_width=True):
            del st.session_state.username
            del st.session_state.my_priv
            st.rerun()
    else:
        mode = st.radio("Access Mode", ["Register", "Login"])
        if mode == "Register":
            username = st.text_input("New Username")
            if st.button("Register & Generate Keypair", use_container_width=True):
                if username.strip():
                    pub_key, priv_key = st.session_state.engine.generate_keypair()
                    success, message = st.session_state.db.register_profile(username.strip(), pub_key)
                    if success:
                        st.success("Registration Successful!")
                        st.info(f"**Your 1536-bit Private Key:** '{priv_key}'")
                        st.caption("Save this private key securely. This shows up only ONCE")
                        st.session_state.username = username.strip()
                        st.sessio_state.my_priv = priv_key
                    else:
                        st.warning(message)
                else:
                    st.error("Username cannot be empty")
        elif mode == "Login":
            username = st.text_input("Username")
            priv_key_input = st.text_input("Your private key", type="password")
            if st.button("Login", use_container_width=True):
                profile = st.session_state.db.fetch_profile(username.strip())
                if profile:
                    try:
                        priv = int(priv_key_input.strip())
                        engine = st.session_state.engine
                        derived_pub = pow(engine.g, priv, engine.p)
                        stored_pub = int(profile['public_key'])

                        if derived_pub == stored_pub:
                            st.session_state.username = username.strip()
                            st.session_state.my_priv = priv
                            st.success(f"Welcome back, {username}!")
                            st.rerun()
                        else:
                            st.error("Authentication Failed: key doesn't match")
                    except ValueError:
                        st.error("Private key must be a valid integer")
                else:
                    st.error("User identity not found in public directory")
col1, col2 = st.columns(2)

with col1:
    st.header("📤Outbox")
    if "username" in st.session_state:
        recipient = st.text_input("Recipient Username")

        engine_choice = st.selectbox(
            "Select Your Encryption Engine",
            [
                "0x01: Caesar Cipher",
                "0x02: Affine Cipher",
                "0x03: Vigenere Cipher",
                "0x04: Hill Cipher"
            ]
        )
        engine_id = int(engine_choice.split(":")[0], 16)

        custom_key = None
        use_manual_key = st.checkbox("🛠️ Manual Key Lab Mode (Advanced)", value=False)

        if use_manual_key:
            st.warning("Manual mode ignores the secure Shared Secret. Use for testing only.")
            if engine_id == 0x01:
                custom_key = st.number_input("Caesar Shift (0-255)", min_value=0, max_value=255, value=13)
            elif engine_id == 0x02:
                col_a, col_b = st.columns(2)
                with col_a:
                    a_val = st.number_input("Multiplier 'a' (Must be Odd)", min_value=1, max_value=255, value=5, step=2)
                with col_b:
                    b_val = st.number_input("Offset 'b' (0-255)", min_value=0, max_value=255, value=7)
                custom_key = (a_val, b_val)
            elif engine_id == 0x03:
                custom_key = st.text_input("Vigenère Passphrase", value="ORION_PROTOCOL_KEY")
            elif engine_id == 0x04:
                st.caption("2x2 Hill Key Matrix (Determinant must be odd mod 256):")
                m_c1, m_c2 = st.columns(2)
                with m_c1:
                    k00 = st.number_input("K[0,0]", value=3, step=1)
                    k10 = st.number_input("K[1,0]", value=2, step=1)
                with m_c2:
                    k01 = st.number_input("K[0,1]", value=5, step=1)
                    k11 = st.number_input("K[1,1]", value=7, step=1)
                custom_key = [[int(k00), int(k01)], [int(k10), int(k11)]]
        else:
            st.info("✨ **Auto-Key Generation** active. Keys are derived from 1536-bit Shared Secret.")
        plaintext = st.text_area("Plaintext Message Payload")

        if st.button("🚀 Sign, Encrypt & Transmit", type="primary", use_container_width=True):
            if not recipient.strip():
                st.error("Recipient username required.")
            elif not plaintext.strip():
                st.error("Plaintext message cannot be empty.")
            else:
                profile = st.session_state.db.fetch_profile(recipient.strip())
                if profile:
                    try:
                        recip_pub = int(profile['public_key'])

                        ciphertext_hex, key_payload = st.session_state.engine.send_message(
                            plaintext=plaintext,
                            recipient_public_key=recip_pub,
                            engine_id=engine_id,
                            key_param=custom_key
                        )

                        success = st.session_state.db.upload_message(
                            sender=st.session_state.username,
                            recipient=recipient.strip(),
                            ciphertext=ciphertext_hex,
                            encrypted_key_json=key_payload
                        )

                        if success:
                            st.success(f"Wire packet successfully transmitted to **{recipient}**!")
                        else:
                            st.error("Transmission error: Database rejected upload.")
                    except Exception as ex:
                        st.error(f"Cryptographic failure: {ex}")
                else:
                    st.error(f"Recipient '{recipient}' not found.")

with col2:
    st.header("📥 Inbox")
    if "username" in st.session_state:
        if st.button("Refresh Data stream", use_container_width = True):
            st.session_state.inbox_msgs = st.session_state.db.fetch_messages(st.session_state.username)

        if "purged_ids" not in st.session_state:
            st.session_state.purged_ids = set()

        msgs = st.session_state.get("inbox_msgs", [])
        if not msgs:
            st.info("No message found.")
        else:
            for msg in msgs:
                msg_id = msg['id']
                is_purged = msg_id in st.session_state.purged_ids

                dec_result = st.session_state.engine.receive_message(
                    ciphertext_hex=msg['ciphertext'],
                    encrypted_key_json=msg['encrypted_key_json'],
                    recipient_private_key=st.session_state.my_priv
                )

                created_time_str = msg['created_at'][:19].replace("T", " ")
                expander_title = f"From {msg['sender']} |  Received: {created_time_str}"

                with st.expander(expander_title, expanded=True):
                    if dec_result["Success"]:
                        st.markdown(f"**Plaintext:** '{dec_result['plaintext']}'")

                        b1, b2, b3 = st.columns(3)
                        with b1:
                            st.success(f"**SSCI Unmasked: ** {dec_result['engine_name']}")
                        with b2:
                            st.success("**HMAC-SHA256** Validated")
                        with b3:
                            current_epoch = int(time.time())
                            age = current_epoch - dec_result['timestamp']
                            st.info(f"⏱️ **Packet Age:** {age}s (Anti-Replay Pass)")
                    else:
                        st.error(f"⚠️ Security Exception: {dec_result['error']}")

                    col_purge, col_dismiss = st.columns(2)
                    with col_purge:
                        if st.button("☁️ Purge from Cloud", key=f"del_{msg_id}", disabled=is_purged,
                                     use_container_width=True):
                            if st.session_state.db.delete_message(msg_id):
                                st.session_state.purged_ids.add(msg_id)
                                st.rerun()
                            else:
                                st.error("Purge request rejected by datastore.")
                    with col_dismiss:
                        if st.button("👁️ Dismiss Local", key=f"dismiss_{msg_id}", use_container_width=True):
                            st.session_state.inbox_msgs = [m for m in st.session_state.inbox_msgs if m['id'] != msg_id]
                            st.rerun()











