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
    st.session_state.db = DBManager()

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
        if st.button("Switch User (Logout)", use_container_width=True):
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
                    success, message = st.session_state.db.register_profile(username.strip(), str(pub_key))
                    if success:
                        st.success("Registration Successful!")
                        st.info(f"**Your 1536-bit Private Key:** '{priv_key}'")
                        st.caption("Save this private key securely. This shows up only ONCE")
                        st.session_state.username = username.strip()
                        st.session_state.my_priv = priv_key
                        if st.button("I have saved my key — Enter EVE"):
                            st.rerun()
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
    st.caption("⚠️ Messages are only accessible within 24 hours of transmission. Check your inbox regularly.")
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
                    if dec_result["success"]:
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
    else:
        st.warning("Authenticate in the sidebar to access encrypted inbox")

st.markdown("""
    <style>
        .eve-container {
            background-color: #0e1117;
            border: 2px solid #ff4b4b;
            padding: 25px;
            border-radius: 10px;
            color: #f0f2f6;
            margin-top: 25px;
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
st.sidebar.subheader("Adversary Telemetry")
hacker_mode = st.sidebar.toggle("Initialize EVE interception")

if hacker_mode:
    st.markdown('<div class="eve-container">', unsafe_allow_html=True)
    st.markdown('<h2 class="eve-header"> Eve\'s Interception & Cryptanalysis Console</h2>', unsafe_allow_html=True)
    st.markdown('<p class="eve-mono">Real-time network tap targeting the database.</p>', unsafe_allow_html=True)

    target_username = st.text_input("Target User Network Tap", placeholder="e.g., Alice")
    if "intercepted_msgs" not in st.session_state:
        st.session_state.intercepted_msgs = []

    if st.button("Tap Cloud Traffic Data Stream", type="primary"):
        if not target_username.strip():
            st.error("Specify target username to isolate network tap.")
        else:
            captured = st.session_state.db.fetch_targeted_messages(target_username.strip())
            st.session_state.intercepted_msgs = captured
            if not captured:
                st.warning(f"No traffic recorded for target user'{target_username}'.")
            else:
                st.success(f"Tap Active: {len(captured)} raw wire packets isolated.")

    if st.session_state.intercepted_msgs:
        packet_options = {
            f"{m['sender']} -> {m['recipient']} ({m['created_at'][:19]}) | ID: {m['id'][:8]}": m
            for m in st.session_state.intercepted_msgs
        }
        selected_label = st.selectbox("Select Intercepted Wire Packet:", list(packet_options.keys()))
        target_packet = packet_options[selected_label]
        raw_hex = target_packet['ciphertext']

        st.markdown("### Wire Protocol Decomposition")
        try:
            raw_bytes = bytes.fromhex(raw_hex)
            sig_hex = raw_bytes[:32].hex()
            masked_engine_hex = f"0x{raw_bytes[32]:02X}"
            payload_hex = raw_bytes[33:].hex()

            t1, t2, t3 = st.colums([2, 1, 3])
            with t1:
                st.text_input("HMAC-SHA256 Signature (32B)", value=sig_hex, disabled=True)
            with t2:
                st.text_input("SSCI Masked Engine ID (1B)", value=masked_engine_hex, disabled=True)
            with t3:
                st.text_input("Ciphertext Payload (C)", value=payload_hex, disabled=True)
        except Exception:
            st.code(raw_hex, language="text")

        st.subheader("Select Cryptanalysis Vector")
        attack_mode = st.radio(
            "Choose Vector Profile:",
        [
                    "1. HMAC Integrity Tamper Simulator",
                    "2. SSCI Obfuscation Analysis",
                    "3. Exhaustive Shift Matrix",
                    "4. Frequency Distribution Spectrum"
                ],
                horizontal=True
            )
        if attack_mode == "1. HMAC Integrity Tamper Simulator":
            st.markdown("#### Bit-Flipping & Integrity Verification Probe")
            st.caption(
                "Inject bit-level mutations into the intercepted wire packet to test HMAC-SHA256 integrity enforcement.")

            tamper_byte_idx = st.slider("Select Byte Offset to Corrupt:", min_value=0,
                                        max_value=max(0, len(raw_bytes) - 1), value=33)
            tamper_mask = st.selectbox("Corrupting XOR Mask:", [0x01, 0x02, 0x04, 0x80, 0xFF],
                                       format_func=lambda x: f"XOR with 0x{x:02X}")

            tampered_bytes = bytearray(raw_bytes)
            tampered_bytes[tamper_byte_idx] ^= tamper_mask
            tampered_hex = tampered_bytes.hex()

            col_orig, col_tamp = st.columns(2)
            with col_orig:
                st.markdown("**Original Wire Packet:**")
                st.code(raw_hex, language="text")
            with col_tamp:
                st.markdown("**Tampered Wire Packet:**")
                st.code(tampered_hex, language="text")

            if "my_priv" in st.session_state:
                test_result = st.session_state.engine.receive_message(
                    ciphertext_hex=tampered_hex,
                    encrypted_key_json=target_packet['encrypted_key_json'],
                    recipient_private_key=st.session_state.my_priv
                )
                if not test_result["success"]:
                    st.success(f"🛡️ **Integrity Verification Success:** {test_result['error']}")
                else:
                    st.error("⚠️ CRITICAL FAILURE: Tampered packet bypassed integrity verification!")
            else:
                st.info("Log in with recipient credentials to test client-side tamper rejection.")

        elif attack_mode == "2. SSCI Obfuscation Analysis":
            st.markdown("#### Shared-Secret Cipher Identification (SSCI) Cryptanalysis")
            st.caption(
                "Demonstrating that the masked Engine ID prevents passive engine determination without the DH shared secret.")

            st.info(f"**Observed Wire Engine Byte:** `{masked_engine_hex}`")
            st.write(
                "Without $S_{\\text{ssci}} = \\operatorname{SHA256}(S)[0]$, the attacker must evaluate all 4 possible engine hypotheses blindly:")

            hypotheses = []
            for candidate_id, name in [(0x01, "Caesar"), (0x02, "Affine"), (0x03, "Vigenère"), (0x04, "Hill")]:
                hypotheses.append({
                    "Hypothesis Engine ID": f"0x{candidate_id:02X} ({name})",
                    "Required Mask Byte S_ssci": f"0x{(raw_bytes[32] ^ candidate_id):02X}",
                    "Complexity Bound": "O(N_engines) brute-force required"
                })
            st.dataframe(pd.DataFrame(hypotheses), use_container_width=True)

        elif attack_mode == "3. Exhaustive Shift Matrix":
            st.markdown("#### Exhaustive Caesar Shift Search")
            brute_results = []
            sample_text = payload_hex[:64]
            for shift in range(1, 26):
                candidate_text = st.session_state.engine.apply_caesar(sample_text, shift, decrypt=True)
                brute_results.append({"Shift Key": shift, "Decrypted Stream Sample": candidate_text})
            st.dataframe(pd.DataFrame(brute_results), use_container_width=True)

        elif attack_mode == "4. Frequency Distribution Spectrum":
            st.markdown("#### Intercepted Byte Frequency Spectrum")
            byte_counts = collections.Counter(raw_bytes)
            freq_df = pd.DataFrame(
                [{"Byte (Hex)": f"0x{k:02X}", "Frequency": v} for k, v in byte_counts.most_common(20)]
            )
            chart = alt.Chart(freq_df).mark_bar(color='#ff4b4b').encode(
                x=alt.X('Byte (Hex):N', sort=None, title='Intercepted Byte Vector'),
                y=alt.Y('Frequency:Q', title='Count'),
                tooltip=['Byte (Hex)', 'Frequency']
            ).properties(height=320)
            st.altair_chart(chart, use_container_width=True)

        st.markdown('</div>', unsafe_allow_html=True)












