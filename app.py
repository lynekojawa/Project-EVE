import streamlit as st
from cipher_engine import CryptoEngine
from db_manager import DBManager

st.set_page_config(page_title = "Project EVE", layout = "wide")
st.title("Project EVE")

if "engine" not in st.session_state:
    st.session_state.engine = CryptoEngine()
if "db" not in st.session_state:
    st.session_state.db = DBManager()

with st.sidebar:
    st.title("EVE identity")

    st.warning("""
            ⚠️ **This is a cryptographic demo.**
            Do not use real personal information. 
            **Private keys are shown once** — save them immediately.
            """)

    if "username" in st.session_state:
        st.success(f"Logged in as **{st.session_state.username}**")

        if st.button("Switch User (Logout)"):
            del st.session_state.username
            del st.session_state.my_priv
            st.rerun()

    else:

        mode = st.radio("Mode", ["Register", "Login"])

        if mode == "Register":
            username = st.text_input("New_Username")
            if st.button("Register & Get Keys"):
                pub_key, priv_key = st.session_state.engine.generate_keypair()
                success, message = st.session_state.db.register_profile(username, pub_key)
                if success:
                    st.success(f"Registered! Your Private key is: '{priv_key}'")
                    st.info("Copy your Private key! You need it to login.")
                    st.session_state.username = username
                    st.session_state.my_priv = priv_key
                else:
                    st.warning(message)

        elif mode == "Login":
            username = st.text_input("Existing Username")
            priv_key_input = st.text_input("Your Private Key", type="password")
            if st.button("Login"):
                profile = st.session_state.db.fetch_profile(username)
                if profile:
                    try:
                        priv = int(priv_key_input)
                        # verify: g^priv mod p should equal stored public key
                        engine = st.session_state.engine
                        derived_pub = pow(engine.g, priv, engine.p)
                        stored_pub = int(profile['public_key_h'])

                        if derived_pub == stored_pub:
                            st.session_state.username = username
                            st.session_state.my_priv = priv
                            st.success(f"Welcome back, {username}!")
                        else:
                            st.error("Wrong private key.")
                    except ValueError:
                        st.error("Private key must be a number.")
                else:
                    st.error("Username not found.")


col1, col2 = st.columns(2)

with col1:
    st.header("📤Outbox (Sender)")
    if "username" in st.session_state:
        recipient = st.text_input("Recipient Username")
        plaintext = st.text_area("Message")

        if st.button("Encrypt & send"):
            profile = st.session_state.db.fetch_profile(recipient)
            if profile:
                recip_pub = int(profile['public_key_h'])

                ciphertext, key_payload = st.session_state.engine.send_message(plaintext, recip_pub)
                st.session_state.db.upload_message(st.session_state.username, recipient, ciphertext, key_payload)
                st.success(f"Message sent to {recipient}!")
            else:
                st.error("Recipient not found in Directory")

with col2:
    st.header("📥 Inbox (Receiver)")
    if "username" in st.session_state:
        if st.button("Refresh Inbox"):
            st.session_state.inbox_msgs = st.session_state.db.fetch_messages(
                st.session_state.username
            )

        if "purged_ids" not in st.session_state:
            st.session_state.purged_ids = set()

        msgs = st.session_state.get("inbox_msgs", [])

        if not msgs:
            st.info("No messages found.")
        else:
             for msg in msgs:
                already_purged = msg['id'] in st.session_state.purged_ids
                if already_purged:
                    decrypted_text = "☁️ Deleted from Cloud"
                else:
                    try:
                        decrypted_text = "Deleted from Cloud" if already_purged else st.session_state.engine.receive_message(
                            msg['ciphertext'], msg['encrypted_key_json'], st.session_state.my_priv
                        )
                    except Exception as e:
                        decrypted_text = f"Decryption Failed: {e}"

                with st.expander(f"From {msg['sender']} (at {msg['created_at'][:19]})"):
                    st.write(f"**Plaintext** {decrypted_text}")

                    col_purge, col_dismiss = st.columns(2)

                    with col_purge:
                        if st.button("☁️ Purge From Cloud",
                                        key=f"del_{msg['id']}",
                                        disabled=already_purged):
                            success = st.session_state.db.delete_message(msg['id'])
                            if success:
                                st.session_state.purged_ids.add(msg['id'])
                                st.session_state.inbox_msgs = [
                                m for m in st.session_state.inbox_msgs
                                    if m['id'] != msg['id']
                                ]

                                st.rerun()
                            else:
                                st.error("Purge request failed.")

                        with col_dismiss:
                            if st.button("👁️ Dismiss", key=f"dismiss_{msg['id']}"):
                                st.session_state.db.delete_message(msg['id'])
                                st.session_state.inbox_msgs = [
                                    m for m in st.session_state.inbox_msgs
                                    if m['id'] != msg['id']
                                ]
                                st.rerun()

    else:
        st.warning("Please login in the sidebar first!")
