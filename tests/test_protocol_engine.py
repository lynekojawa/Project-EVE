"""
Project EVE v2.1 — Phase 2 Audit Script
Grand Protocol Engine Test Suite v2.4 — Full Transparency Mode
"""
import time
import struct
import hmac
import hashlib
import secrets
from cipher_arsenal.cipher_arsenal import CipherFactory
from protocol_engine.protocol_engine import (
    WireProtocolEngine,
    KDFEngine,
    HMACVerificationError,
    ReplayAttackError,
    ClockSkewError,
    ProtocolError
)

TEST_SECRET = 123456789012345678901234567890
TEST_MESSAGE = "JOBS-RESEARCHER@REDBALLOONSECURITY.COM"

def section(title: str):
    print(f"\n{'═' * 70}")
    print(f"  {title}")
    print(f"{'═' * 70}")

def subsection(title: str):
    print(f"\n  {'─' * 60}")
    print(f"  {title}")
    print(f"  {'─' * 60}")

def run_standard_roundtrip_tests():
    section("STANDARD ROUND-TRIP TESTS — Full Transparency")

    test_configs = {
        0x01: {"name": "Caesar",   "key": 42},
        0x02: {"name": "Affine",   "key": (15, 7)},
        0x03: {"name": "Vigenere", "key": "GRAPE_POWER"},
        0x04: {"name": "Hill",     "key": [[6, 24, 1], [13, 16, 10], [20, 17, 15]]},
    }

    for engine_id, config in test_configs.items():
        name = config["name"]
        key = config["key"]

        subsection(f"Engine 0x{engine_id:02X} — {name}")

        try:
            print(f"  📝 Plaintext   : '{TEST_MESSAGE}'")
            print(f"  🔑 Key         : {key}")

            packet_hex = WireProtocolEngine.pack_message(
                TEST_MESSAGE, engine_id,
                key_param=key,
                shared_secret_int=TEST_SECRET
            )

            print(f"  📦 Wire Packet : {packet_hex[:32]}...{packet_hex[-16:]} ({len(packet_hex)//2} bytes)")
            print(f"  🔍 Structure   :")
            print(f"     ├─ HMAC Signature (32B) : {packet_hex[:64]}")
            print(f"     ├─ E_masked (1B)         : {packet_hex[64:66]}")
            print(f"     └─ Ciphertext Body       : {packet_hex[66:130]}...")

            recovered_id, plaintext, ts = WireProtocolEngine.unpack_message(
                packet_hex, TEST_SECRET, override_key_param=key
            )

            print(f"  🔓 Decrypted   : '{plaintext}'")
            print(f"  🆔 Engine ID   : 0x{recovered_id:02X} (expected 0x{engine_id:02X})")
            print(f"  🕐 Timestamp   : {ts} ({time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))})")
            print(f"  ✅ MATCH       : {plaintext == TEST_MESSAGE}")

        except Exception as e:
            print(f"  ❌ FAILED: {e}")

def run_auto_key_derivation_test():
    section("AUTO KEY DERIVATION TEST — Hill Matrix from KDF")

    subsection("Hill (0x04) — No Manual Key")
    try:
        k_enc, k_mac, s_ssci = KDFEngine.derive_keys(TEST_SECRET)
        print(f"  🔑 K_enc (first 16B) : {k_enc.hex()[:32]}...")

        packet_hex = WireProtocolEngine.pack_message(
            TEST_MESSAGE, 0x04,
            key_param=None,
            shared_secret_int=TEST_SECRET
        )

        print(f"  📦 Wire Packet       : {packet_hex[:32]}...{packet_hex[-16:]} ({len(packet_hex)//2} bytes)")

        recovered_id, plaintext, ts = WireProtocolEngine.unpack_message(
            packet_hex, TEST_SECRET, override_key_param=None
        )

        print(f"  🔓 Decrypted         : '{plaintext}'")
        print(f"  ✅ MATCH             : {plaintext == TEST_MESSAGE}")

    except Exception as e:
        print(f"  ❌ FAILED: {e}")

def run_kdf_isolation_test():
    section("KDF SUB-KEY DERIVATION — Isolation Verification")

    k_enc, k_mac, s_ssci = KDFEngine.derive_keys(TEST_SECRET)

    print(f"\n  🔐 Shared Secret (truncated) : {str(TEST_SECRET)[:20]}...")
    print(f"\n  K_enc  (32B) : {k_enc.hex()}")
    print(f"  K_mac  (32B) : {k_mac.hex()}")
    print(f"  S_ssci (1B)  : 0x{s_ssci:02X} ({s_ssci} decimal)")

    print(f"\n  Distinctness checks:")
    print(f"  ├─ K_enc != K_mac  : {k_enc != k_mac}")
    print(f"  ├─ K_enc[0] = {k_enc[0]:3d} | K_mac[0] = {k_mac[0]:3d} | S_ssci = {s_ssci:3d}")
    print(f"  └─ Engine ID 0x01 masked : 0x01 XOR 0x{s_ssci:02X} = 0x{0x01 ^ s_ssci:02X}")

def run_adversarial_tests():
    section("ADVERSARIAL TESTS — Security Guard Verification")

    # Test 1 — HMAC tampering
    subsection("TEST 1: HMAC Bit-Flip Tampering")
    try:
        packet = WireProtocolEngine.pack_message(
            TEST_MESSAGE, 0x01, key_param=42,
            shared_secret_int=TEST_SECRET
        )
        packet_bytes = bytearray(bytes.fromhex(packet))
        original_byte = packet_bytes[40]
        packet_bytes[40] ^= 0xFF
        print(f"  🔨 Flipped byte[40]: 0x{original_byte:02X} → 0x{packet_bytes[40]:02X}")
        tampered = bytes(packet_bytes).hex()
        WireProtocolEngine.unpack_message(tampered, TEST_SECRET, override_key_param=42)
        print("  ❌ Should have raised HMACVerificationError")
    except HMACVerificationError as e:
        print(f"  🛡️  Caught: {type(e).__name__}")
        print(f"  ✅ Tampering correctly detected")

    # Test 2 — Replay attack
    subsection("TEST 2: Replay Attack (120s old packet)")
    try:
        k_enc, k_mac, s_ssci = KDFEngine.derive_keys(TEST_SECRET)
        old_time = int(time.time()) - 120
        time_prefix = struct.pack(">Q", old_time)
        raw = time_prefix + TEST_MESSAGE.encode("utf-8")
        iv = secrets.token_bytes(8)
        p_final = bytes(raw[i] ^ iv[i % 8] for i in range(len(raw)))

        engine = CipherFactory.get_engine(0x01)
        ciphertext = engine.encrypt(p_final, k_enc[0]) + iv
        e_masked = bytes([0x01 ^ s_ssci])
        mac_payload = e_masked + ciphertext
        signature = hmac.new(k_mac, mac_payload, hashlib.sha256).digest()
        wire_packet = (signature + mac_payload).hex()

        print(f"  🕐 Packet timestamp : {old_time} (120s ago)")
        print(f"  🕐 Current time     : {int(time.time())}")
        print(f"  ⏱️  Delta            : {int(time.time()) - old_time}s (limit: {WireProtocolEngine.DRIFT_MAX_SECONDS}s)")

        WireProtocolEngine.unpack_message(wire_packet, TEST_SECRET, override_key_param=k_enc[0])
        print("  ❌ Should have raised ReplayAttackError")
    except ReplayAttackError as e:
        print(f"  🛡️  Caught: {type(e).__name__}")
        print(f"  ✅ Replay attack correctly rejected")

    # Test 3 — Wrong shared secret
    subsection("TEST 3: Wrong Shared Secret")
    try:
        packet = WireProtocolEngine.pack_message(
            TEST_MESSAGE, 0x01, key_param=42,
            shared_secret_int=TEST_SECRET
        )
        wrong_secret = TEST_SECRET + 1
        print(f"  🔑 Original secret (last 8 digits) : ...{str(TEST_SECRET)[-8:]}")
        print(f"  🔑 Wrong secret    (last 8 digits) : ...{str(wrong_secret)[-8:]}")
        WireProtocolEngine.unpack_message(packet, wrong_secret, override_key_param=42)
        print("  ❌ Should have raised HMACVerificationError")
    except HMACVerificationError as e:
        print(f"  🛡️  Caught: {type(e).__name__}")
        print(f"  ✅ Wrong secret correctly rejected")

    # Test 4 — Truncated packet
    subsection("TEST 4: Truncated Packet")
    try:
        print(f"  📦 Sending: 'deadbeef' (4 bytes — minimum is 41 bytes)")
        WireProtocolEngine.unpack_message("deadbeef", TEST_SECRET)
        print("  ❌ Should have raised ProtocolError")
    except ProtocolError as e:
        print(f"  🛡️  Caught: {type(e).__name__}: {e}")
        print(f"  ✅ Truncated packet correctly rejected")

    # Test 5 — Invalid hex
    subsection("TEST 5: Invalid Hex Encoding")
    try:
        print(f"  📦 Sending: 'not_valid_hex!!'")
        WireProtocolEngine.unpack_message("not_valid_hex!!", TEST_SECRET)
        print("  ❌ Should have raised ProtocolError")
    except ProtocolError as e:
        print(f"  🛡️  Caught: {type(e).__name__}: {e}")
        print(f"  ✅ Invalid hex correctly rejected")

if __name__ == "__main__":
    print("🚀 [INIT] Grand Protocol Audit v2.4 — Full Transparency Mode")
    print(f"  Test Message : '{TEST_MESSAGE}'")
    print(f"  Shared Secret: {str(TEST_SECRET)[:10]}...{str(TEST_SECRET)[-10:]}")

    run_kdf_isolation_test()
    run_standard_roundtrip_tests()
    run_auto_key_derivation_test()
    run_adversarial_tests()

    print(f"\n{'═' * 70}")
    print("🏆 Protocol Engine Audit v2.4 Complete.")
    print(f"{'═' * 70}")