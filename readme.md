# Project EVE
[![Live Demo](https://img.shields.io/badge/Live-Demo-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://project-eve-hypadrnwddav6olyyq6ay7.streamlit.app/)
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

# EVE v2.1 — Architecture

## What Changed

EVE v1 demonstrated that ElGamal key exchange is cryptographically sound while Caesar encryption is not. The Eve Analysis dashboard proved that point by breaking Caesar in seconds.

EVE v2.1 takes the next step: a genuinely hardened system. Same client-side key architecture. Same ElGamal key exchange. Everything else upgraded.

---

## Cipher Factory

Four cipher engines behind a unified interface. Every engine implements the same contract:

```
encrypt(plaintext, key) → ciphertext
decrypt(ciphertext, key) → plaintext
```

| Engine | Key Type | Notes |
|---|---|---|
| Caesar | Integer shift | Legacy baseline |
| Affine | (a, b) scalar pair | Requires gcd(a, 26) = 1 |
| Vigenère | String keyword | Polyalphabetic — resists frequency analysis |
| Hill | n×n invertible matrix | Leverages Determinant Engine finite field arithmetic |

The Hill cipher engine reuses the matrix inversion logic from Project 2 (Determinant Engine) — the first time that tool has been called as a dependency in production code.

A dynamic UI selector switches engines at session time. Key input fields adapt to the selected cipher type.

---

## Shared-Secret Cipher Identification (SSCI)

The engine used to encrypt a message is not stored in plaintext. Instead, a 1-byte Engine ID is masked using the ElGamal shared secret:

```
mask = Hash(K)[0]
stored_header = Engine_ID XOR mask
```

Without the recipient's private key, an attacker cannot recover K, cannot unmask the header, and cannot determine which cipher was used. This forces blind brute-force across all four engines simultaneously.

---

## Cryptographic Integrity Layer (HMAC-SHA256)

Every message packet carries a 32-byte HMAC-SHA256 tag computed over the ciphertext:

```
tag = HMAC-SHA256(shared_secret, ciphertext)
packet = ciphertext || tag
```

On receipt, the tag is verified before decryption begins. Any tampering with the stored ciphertext — including database-level modification — produces a signature mismatch and triggers a security alert. Confidentiality and integrity are now separate guarantees.

---

## Temporal Defense — Anti-Replay

Unix timestamps are injected into the plaintext before encryption:

```
P_final = Timestamp || Original_Message
```

On decryption, if the recovered timestamp falls outside the allowed drift window (> 60 seconds), the message is rejected. Replayed packets — valid ciphertext resent by an attacker — cannot pass this check.

Edge case documented: clock skew between sender and receiver may cause false rejections. Drift window is configurable.

---

## Supabase RLS Re-hardening

Row Level Security re-enabled with strict uid = auth.uid() policies. Users can read and write only their own records. Hacker Mode demonstrations run via Service-Role Key emulation in a sandboxed context — proving the system is secure by design, not by accident.

---

## Project Lineage

| Version | Symmetric Layer | Integrity | Replay Protection | Cipher Obfuscation |
|---|---|---|---|---|
| v1.0 | Caesar | None | None | None |
| v2.1 | Caesar / Affine / Vigenère / Hill | HMAC-SHA256 | Timestamp | SSCI via shared secret |

The Eve Analysis dashboard remains. It now demonstrates why Caesar and Affine fall while Vigenère and Hill resist naive frequency analysis — and why none of them replace modern symmetric encryption.
⚠️ This is a cryptographic demo. Do not use real personal information. 
Private keys are shown once — save them immediately.

## 🤝 Project Credits
This project was developed through a high-entropy collaboration between human intuition and AI orchestration:

| Role                   | Contributor         | Responsibility                        |
|:-----------------------|:--------------------|:--------------------------------------|
| **Lead Architect**     | lynekojawa (Human)  | Core Idea, Audit, Math                |
| **Logic Orchestrator** | PODO (Gemini)       | System Design, Logic   |
| **Master Planner**     | Orion (Gemini)      | Strategic Planning                    |
| **Code Partner**       | Dante (Claude)      | Git Strategy, Implementation, Review  |
| **Code Review**        | mini-Dante (Claude) | Implementation, Review, finding Error |