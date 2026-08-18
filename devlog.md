(8/11)

Initiated the project, update for the EVE, the plans are following:<br>
add more engine, add digital signature,  Caesar / Affine / Vigenère / Hill | HMAC-SHA256 | Timestamp | SSCI via shared secret.<br>
We will see how this works, already spotted logic leaking, my agent made a code by only looking at ui codes... <br> 
In the middle of updating engine, tomorrow I will continue from Hill cipher. <br>

(8/12)<br>
Continue the project, writing from Hill Cipher. <br>
This is very challenging, has lots of bounce bump, not only I need to make sure code runs, I also need to think about what's more efficiency or not. <br>

(8/13)<br>
part1<br>
Continued, phase 1 confirmed by podos and orion, and mini-dante, run the test,<br>
🚀 Starting Grand Arsenal Audit for: 'Imperial Protocol v2.1 - Hello PODO!'

------------------------------------------------------------
✅ [0x01] Caesar     : SUCCESS
    └─ Ciphertext(hex): 73979a8f9c938b964a7a9c999e998d99964aa05c585b4a574a...
✅ [0x02] Affine     : SUCCESS
    └─ Ciphertext(hex): 4e6a97f2b52eb65be7b7b588d388d4885be7f1f5b9e6e7aae7...
✅ [0x03] Vigenere   : SUCCESS
    └─ Ciphertext(hex): 90bfb1b5b7c8b1bb7795c4b6c6b0b3b4cb70c5897383677f61...
✅ [0x04] Hill       : SUCCESS
    └─ Ciphertext(hex): 5ee581775b9d86eda0ff865383b23cdaa3b8a2ea3c533f97e5...
🏆 All engines are operational and algebraically sound!
and output looks solid. 
part2<br>
initiated phase 2 with Orion, waiting for Dante's response. 
it kinda make sense why for all lecture notes and textbooks says (keyGen, Enc, Dec) and they are all written as Tuple <br>
gosh, I was working on protocol_engine today and Orion only gave me 2 engines, is this a sign of drift or lazyness. For real<br>

(8/17)
Continue on the project starting with Dante's comments. <br> 
First, Artisan vs Efficiency, currently my Hill code does modular at the end, but to reduce computation time, doing modulars<br>
between each recursive step is better. <br> 
Second, no mod_inverse in encryption, for efficiency use when decrypt but no encrypt <br>
Before moving back to phase 2 updating script test: one, add Edge cases, Two, add affine invalid key text<br>
Passed all test with edge cases. <br>
Phase 2 auditing the Orion's script timestamp 6:00pm-> finished transcribe working on logic. <br>
Podo reported following, one. Deterministic key derivation in hill matrix,two, SSCI potential leaking, Three, Stability vs strictness<br>
fixing those three parts. <br>
Podo's audit added inspection tomorrow with mini-dante and mini-podo. 

(8/19)
Continue the project, inspect with mini-podo and dante: <br>
Phase 2 — Protocol & Security Layer Fixes
Fixed HMAC API call
Replaced invalid hmac.net() with hmac.new() in WireProtocolEngine.pack_message().
Fixed effective key resolver reference
Corrected _resolved_effective_key() to _resolve_effective_key() in WireProtocolEngine.unpack_message().
Fixed replay attack time-window validation
Changed the replay threshold from DRIFT_MIN_SECONDS to DRIFT_MAX_SECONDS.
Correctly enforces the intended -30s ≤ delta_t ≤ +60s acceptance window.
Enforced strict UTF-8 decoding
Removed errors='replace'.
Invalid UTF-8 now raises ProtocolError instead of silently replacing malformed bytes.
Unified Hill cipher key derivation
Updated engine_id == 0x04 to use _derive_hill_matrix(k_enc).
Connects the deterministic, entropy-derived Hill matrix generator to the actual key-resolution path.
mini-podo audit-> fixed. -> move to dante
🚀 [INIT] Grand Protocol Audit v2.4 — Full Transparency Mode
  Test Message : 'The quick brown fox jumps over the lazy dog'
  Shared Secret: 1234567890...1234567890

══════════════════════════════════════════════════════════════════════
  KDF SUB-KEY DERIVATION — Isolation Verification
══════════════════════════════════════════════════════════════════════

  🔐 Shared Secret (truncated) : 12345678901234567890...

  K_enc  (32B) : 078f9a5553b8f2a40e81dc16e44b3535a0313ffc93cb457c96a1824ae871be60
  K_mac  (32B) : 920220b6b290e622dbe02422ec8ff87a507f2d25d9f5ce29be84a93750ded0a9
  S_ssci (1B)  : 0x33 (51 decimal)

  Distinctness checks:
  ├─ K_enc != K_mac  : True
  ├─ K_enc[0] =   7 | K_mac[0] = 146 | S_ssci =  51
  └─ Engine ID 0x01 masked : 0x01 XOR 0x33 = 0x32

══════════════════════════════════════════════════════════════════════
  STANDARD ROUND-TRIP TESTS — Full Transparency
══════════════════════════════════════════════════════════════════════

  ────────────────────────────────────────────────────────────
  Engine 0x01 — Caesar
  ────────────────────────────────────────────────────────────
  📝 Plaintext   : 'The quick brown fox jumps over the lazy dog'
  🔑 Key         : 42
  📦 Wire Packet : bfc55c700526755e567a09146815897d...968ba4a34a8e9991 (84 bytes)
  🔍 Structure   :
     ├─ HMAC Signature (32B) : bfc55c700526755e567a09146815897d861965f8cab3554a84197de065a09890
     ├─ E_masked (1B)         : 32
     └─ Ciphertext Body       : 2a2a2a2a94aef7927e928f4a9b9f938d954a8c9c99a1984a9099a24a949f979a...
  🔓 Decrypted   : 'The quick brown fox jumps over the lazy dog'
  🆔 Engine ID   : 0x01 (expected 0x01)
  🕐 Timestamp   : 1787088232 (2026-08-18 17:23:52)
  ✅ MATCH       : True

  ────────────────────────────────────────────────────────────
  Engine 0x02 — Affine
  ────────────────────────────────────────────────────────────
  📝 Plaintext   : 'The quick brown fox jumps over the lazy dog'
  🔑 Key         : (15, 7)
  📦 Wire Packet : 30a649e8a93681d4c3d8c259225ac019...5bb62d1ee7e38810 (84 bytes)
  🔍 Structure   :
     ├─ HMAC Signature (32B) : 30a649e8a93681d4c3d8c259225ac0197ba1cc74a5a4de2b88f6dda5e0fc060c
     ├─ E_masked (1B)         : 31
     └─ Ciphertext Body       : 070707073dc30a1ff31ff2e7a6e22ed44ce7c5b5880079e701880fe73de26a97...
  🔓 Decrypted   : 'The quick brown fox jumps over the lazy dog'
  🆔 Engine ID   : 0x02 (expected 0x02)
  🕐 Timestamp   : 1787088232 (2026-08-18 17:23:52)
  ✅ MATCH       : True

  ────────────────────────────────────────────────────────────
  Engine 0x03 — Vigenere
  ────────────────────────────────────────────────────────────
  📝 Plaintext   : 'The quick brown fox jumps over the lazy dog'
  🔑 Key         : GRAPE_POWER
  📦 Wire Packet : fde091aa9530cd6562b84fb27217a8c0...bea8ccba70a9ceb7 (84 bytes)
  🔍 Structure   :
     ├─ HMAC Signature (32B) : fde091aa9530cd6562b84fb27217a8c075a6d6402c7d28c73ba19644051e5284
     ├─ E_masked (1B)         : 30
     └─ Ciphertext Body       : 47524150afe31db7abadb767c3b6b9a8ca70b1c9b4c9b572a7bfbd7fbac4c4b5...
  🔓 Decrypted   : 'The quick brown fox jumps over the lazy dog'
  🆔 Engine ID   : 0x03 (expected 0x03)
  🕐 Timestamp   : 1787088232 (2026-08-18 17:23:52)
  ✅ MATCH       : True

  ────────────────────────────────────────────────────────────
  Engine 0x04 — Hill
  ────────────────────────────────────────────────────────────
  📝 Plaintext   : 'The quick brown fox jumps over the lazy dog'
  🔑 Key         : [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
  📦 Wire Packet : 8786a88df15c93761a825ea81416ed73...0271270a385d759c (87 bytes)
  🔍 Structure   :
     ├─ HMAC Signature (32B) : 8786a88df15c93761a825ea81416ed73b848ec3e07767ae6833c63d7ec39ea20
     ├─ E_masked (1B)         : 37
     └─ Ciphertext Body       : 00000074c8c6e231d808d8b50727c07af7b76b70bb3a2b7a44ce5f25d2658107...
  🔓 Decrypted   : 'The quick brown fox jumps over the lazy dog'
  🆔 Engine ID   : 0x04 (expected 0x04)
  🕐 Timestamp   : 1787088232 (2026-08-18 17:23:52)
  ✅ MATCH       : True

══════════════════════════════════════════════════════════════════════
  AUTO KEY DERIVATION TEST — Hill Matrix from KDF
══════════════════════════════════════════════════════════════════════

  ────────────────────────────────────────────────────────────
  Hill (0x04) — No Manual Key
  ────────────────────────────────────────────────────────────
  🔑 K_enc (first 16B) : 078f9a5553b8f2a40e81dc16e44b3535...
  📦 Wire Packet       : 4fd608c7d6d24f7106d93dd3bb390b6d...3a49dc0365795fe0 (85 bytes)
  🔓 Decrypted         : 'The quick brown fox jumps over the lazy dog'
  ✅ MATCH             : True

══════════════════════════════════════════════════════════════════════
  ADVERSARIAL TESTS — Security Guard Verification
══════════════════════════════════════════════════════════════════════

  ────────────────────────────────────────────────────────────
  TEST 1: HMAC Bit-Flip Tampering
  ────────────────────────────────────────────────────────────
  🔨 Flipped byte[40]: 0x92 → 0x6D
  🛡️  Caught: HMACVerificationError
  ✅ Tampering correctly detected

  ────────────────────────────────────────────────────────────
  TEST 2: Replay Attack (120s old packet)
  ────────────────────────────────────────────────────────────
  🕐 Packet timestamp : 1787088112 (120s ago)
  🕐 Current time     : 1787088232
  ⏱️  Delta            : 120s (limit: 60.0s)
  🛡️  Caught: ReplayAttackError
  ✅ Replay attack correctly rejected

  ────────────────────────────────────────────────────────────
  TEST 3: Wrong Shared Secret
  ────────────────────────────────────────────────────────────
  🔑 Original secret (last 8 digits) : ...34567890
  🔑 Wrong secret    (last 8 digits) : ...34567891
  🛡️  Caught: HMACVerificationError
  ✅ Wrong secret correctly rejected

  ────────────────────────────────────────────────────────────
  TEST 4: Truncated Packet
  ────────────────────────────────────────────────────────────
  📦 Sending: 'deadbeef' (4 bytes — minimum is 41 bytes)
  🛡️  Caught: ProtocolError: Wire packet truncated; fails minimum size requirement
  ✅ Truncated packet correctly rejected

  ────────────────────────────────────────────────────────────
  TEST 5: Invalid Hex Encoding
  ────────────────────────────────────────────────────────────
  📦 Sending: 'not_valid_hex!!'
  🛡️  Caught: ProtocolError: Invalid hexadecimal packet encoding
  ✅ Invalid hex correctly rejected

══════════════════════════════════════════════════════════════════════
Test passed! 
Initializing phase 3! 
SQL ready(kind of) move to DB manager.py