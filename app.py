#Today(5/29) Phase 4 UI updated and Jump into EVE anlaysis :D

import streamlit as st
import pandas as pd
import altair as alt
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

        if "decrypted_cache" not in st.session_state:
            st.session_state.decrypted_cache = {}

        msgs = st.session_state.get("inbox_msgs", [])

        if not msgs:
            st.info("No messages found.")
        else:
             for msg in msgs:
                 if 'decrypted_content' not in msg:
                     try:
                         decrypted_text = st.session_state.engine.receive_message(
                             msg['ciphertext'],
                             msg['encrypted_key_json'],
                             st.session_state.my_priv
                         )
                         msg['decrypted_content'] = decrypted_text
                     except Exception as e:
                         msg['decrypted_content'] = f"Decryption Error:{e}"

                 already_purged = msg['id'] in st.session_state.purged_ids

                 with st.expander(f"From {msg['sender']} (at {msg['created_at'][:19]})"):
                     display_text = f"☁️[Cloud Deleted] {msg['decrypted_content']}" if already_purged else msg[
                         'decrypted_content']
                     st.write(f"**Plaintext** {display_text}")

                     col_purge, col_dismiss = st.columns(2)

                     with col_purge:
                         if st.button("☁️ Purge From Cloud",
                                        key=f"del_{msg['id']}",
                                        disabled=already_purged):
                             success = st.session_state.db.delete_message(msg['id'])
                             if success:
                                st.session_state.purged_ids.add(msg['id'])
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
#divider
st.markdown("""
    <style>
        .eve-container {
            background-color: #0e1117;
            border: 2px solid #ff4b4b;
            padding: 25px;
            border-radius: 10px;
            color: #f0f2f6;
            margin-top: 20px;
        }
        .eve-header {
            color: #ff4b4b !important;
            font-family: 'Courier New', monospace;
        }
        .eve-mono {
            font-family: 'Courier New', monospace;
            color: #a3b8cc;
        }
    </style>
""", unsafe_allow_html=True)


st.sidebar.markdown("---")
st.sidebar.subheader("🕵️‍♂️ Cryptanalysis Control")
hacker_mode = st.sidebar.toggle("⚡ Initialize Eve Interception")


if hacker_mode:
    st.markdown('<div class="eve-container">', unsafe_allow_html=True)
    st.markdown('<h2 class="eve-header">🕵️‍♂️ Eve\'s Interception & Cryptanalysis Console</h2>', unsafe_allow_html=True)
    st.markdown('<p class="eve-mono">Real-time network tap directly targeting the Supabase cloud datastore.</p>',
                unsafe_allow_html=True)
    target_username = st.text_input("Target Username", placeholder="e.g. Alice")
    if "intercepted_msgs" not in st.session_state:
        st.session_state.intercepted_msgs = []

    if st.button("📡 Tap Cloud Traffic Data Stream", type="primary"):
        if not target_username.strip():
            st.error("Please specify a target username to isolate the tap")
        else:
            captured = st.session_state.db.fetch_targeted_messages(target_username.strip())
            st.session_state.intercepted_msgs = captured

            if not captured:
                st.warning(f"Target username {target_username} is not registered.")
            else:
                st.success(f"Interception Established {len(captured)} messages isolated for data stream.")
    if st.session_state.intercepted_msgs:
        st.markdown(f"### Raw Intercepted Ciphertext Messages")
        st.subheader("Select Cipher Cryptanalysis Vector")

        attack_mode = st.radio(
            "Choose Attack Profile:",
            ["1. Brute Force Matrix", "2. Frequency Distribution", "3. Known-Plaintext Attack"],
            horizontal = True
        )

        ciphertexts = [msg['ciphertext'] for msg in st.session_state.intercepted_msgs]

        if attack_mode == "1. Brute Force Matrix":
            st.markdown("#### 25-key Exhaustive Search")
            st.caption("Displaying every single mathematical shift permutation for the first intercepted packet.")

            if ciphertexts:
                message_options = {
                    f"{msg['sender']} -> {msg['recipient']} ({msg['created_at']})" : msg['ciphertext']
                    for msg in st.session_state.intercepted_msgs
                }

                selected_label = st.selectbox(
                    "Intercepted Packet Selector",
                    options = list(message_options.keys())
                )
                target_cipher = message_options[selected_label]
                brute_force_results =[]

                for shift in range(1,26):
                    candidate_text = st.session_state.engine.apply_caesar(target_cipher, shift, decrypt=True)
                    brute_force_results.append({"Shift Key": shift, "Decrypted Candidate Text": candidate_text})

                st.dataframe(brute_force_results, use_container_width = True)
        elif attack_mode == "2. Frequency Distribution":
            st.markdown("#### Linguistic Signature Mapping")
            st.caption("Analyzing character frequency distributions across all messages.")

            message_options = {f"{msg['sender']} ({msg['created_at'][:20]})": msg['ciphertext'] for msg in
                               st.session_state.intercepted_msgs}
            selected_label = st.selectbox("Analyze Packet:", options=list(message_options.keys()))
            target_cipher = message_options[selected_label]

            combined_text = "".join([c for c in target_cipher.upper() if c.isalpha()])

            if not combined_text:
                st.warning("Insufficient alphabetic data intercepted to map a frequency footprint")
            else:
                import collections
                import string

                counts = collections.Counter(combined_text)
                total_char = len(combined_text)

                freq_data = {letter: (counts[letter]/total_char) * 100 for letter in string.ascii_uppercase}
                df = pd.DataFrame(list(freq_data.items()), columns=['Letter', 'Frequency'])

                chart = alt.Chart(df).mark_bar(color='#ff4b4b').encode(
                    x=alt.X('Letter:N', sort=list(string.ascii_uppercase), title='Intercepted Character Vector'),
                    y=alt.Y('Frequency:Q', title='Frequency (%)', scale=alt.Scale(domain=[0, 100])),
                    tooltip=['Letter', 'Frequency']
                ).properties(
                    height=300
                ).configure_axis(
                    grid=False
                )

                st.markdown("### Target Ciphertext")
                st.code(target_cipher, language = "text")
                st.caption(f"{len(target_cipher)} characters")

                st.altair_chart(chart, use_container_width=True)
                st.info("💡 Tip: Look for the highest peaks. In normal English text, those peaks align to E, T, and A. Their offset reveals the key.")


    st.markdown('</div>', unsafe_allow_html=True)