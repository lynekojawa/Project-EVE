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
        if st.button("")