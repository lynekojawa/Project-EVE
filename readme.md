# Project EVE

## 🛡️ Why I Built This
I studied Cryptography in my undergraduate program and wanted to build 
something that applies ElGamal to a real product — not just on paper. 
The goal was simple: send a secret message and feel like a spy doing it.

## 🎯 What It Does
A hybrid E2EE messenger demonstration. ElGamal (1536-bit RFC3526 prime) handles secure 
key exchange. Caesar cipher handles message encryption. All cryptographic 
operations happen client-side — the server stores only ciphertext and 
public keys. Your private key never leaves your machine.

Register a username → get a public/private keypair → send encrypted 
messages to other users → decrypt with your private key.

## 🔑 Cryptographic Implementation
EVE uses a **Hybrid Cryptosystem** to ensure message integrity and privacy:
- **Key Exchange (Asymmetric):** Implements a 1536-bit ElGamal protocol for secure session key exchange.
- **Payload Encryption (Symmetric):** Employs a Caesar-shift variant for payload obfuscation, using cryptographically secure random session keys.
- **Privacy Design:** The server (Supabase) acts as a "blind" repository. Plaintext messages and private keys never touch the database; only ciphertext and public keys are persisted.

## 🏗️ Architecture & Phases

### Phase 1 — Crypto Core
Built the ElGamal engine from scratch: key generation, encrypt/decrypt, 
modular inverse via iterative extended GCD. Verified full round-trip.

### Phase 2 — Backend
Supabase (PostgreSQL) schema with Row Level Security. Two tables: 
eve_profiles (public key directory) and eve_messages (ciphertext storage).

### Phase 3 — Full Stack UI
Streamlit interface connecting crypto engine and database. Register, 
send, receive, decrypt — end to end working.

### Phase 4 — Eve Analysis (In Progress)
Hacker dashboard showing frequency analysis on Caesar ciphertext. 
Demonstrates why Caesar is entertainment, not security — and why 
ElGamal key exchange matters.

## 🛠️ Technical Stack
- **Frontend:** Streamlit
- **Backend:** Supabase (PostgreSQL)
- **Crypto:** Python — secrets, json, logging

## 💡 What I Learned
This was the most complex project I've built so far. Not because of 
any single piece — but because I had to manage frontend, backend, 
cryptographic correctness, and session state simultaneously. 

Turning academic crypto into a working product is a different skill 
than understanding the math. I now know both.

## Current Status
Core messaging fully operational. Eve Analysis dashboard in progress.

⚠️ This is a cryptographic demo. Do not use real personal information. 
Private keys are shown once — save them immediately.

## 🤝 Project Credits
This project was developed through a high-entropy collaboration between human intuition and AI orchestration:

| Role | Contributor | Responsibility |
| :--- | :--- | :--- |
| **Lead Architect** | lynekojawa (Human) | Core Idea, Audit, Math |
| **Logic Orchestrator** | PODO (Gemini) | System Design, Logic, Code Review |
| **Master Planner** | Orion (Gemini) | Strategic Planning |
| **Code Partner** | Dante (Claude) | Git Strategy, Implementation, Review |