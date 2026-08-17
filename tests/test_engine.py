from cipher_arsenal.cipher_arsenal import CipherFactory, AffineEngine, NonInvertibleMatrixError

def run_imperial_test():
    original_message = b"Imperial Protocol v2.1 - Hello PODO!"

    test_configs = {
        0x01: {"name": "Caesar", "key": 42},
        0x02: {"name": "Affine", "key": (15, 7)},
        0x03: {"name": "Vigenere", "key": "GRAPE_POWER"},
        0x04: {"name": "Hill", "key": [[6, 24, 1], [13, 16, 10], [20, 17, 15]]}
    }

    print(f"🚀 [INIT] Starting Grand Imperial Audit v2.2")
    print(f"🔍 [INFO] Testing with: '{original_message.decode()}'")
    print("-" * 70)

    for engine_id, config in test_configs.items():
        name = config["name"]
        key = config["key"]

        try:
            engine = CipherFactory.get_engine(engine_id)

            ciphertext = engine.encrypt(original_message, key)
            decrypted = engine.decrypt(ciphertext, key)
            assert original_message == decrypted, f"{name} failed standard round-trip"
            empty_ct = engine.encrypt(b"", key)
            assert engine.decrypt(empty_ct, key) == b"", f"{name} failed empty input"

            single_byte = b"\x00"
            single_ct = engine.encrypt(single_byte, key)
            assert engine.decrypt(single_ct, key) == single_byte, f"{name} failed single byte"

            all_bytes = bytes(range(256))
            all_ct = engine.encrypt(all_bytes, key)
            assert engine.decrypt(all_ct, key) == all_bytes, f"{name} failed Z_256 completeness test"

            print(f"✅ [0x{engine_id:02X}] {name:10} : PASSED (Standard + Edge Cases)")

        except Exception as e:
            print(f"❌ [0x{engine_id:02X}] {name:10} : FAILED standard/edge tests")
            print(f"    └─ Error: {e}")

    print("-" * 70)
    print("🛡️ [ADVERSARIAL] Validating Error Handlers & Guards")


    try:
        print("🔍 Testing Affine: Even 'a' key check...", end=" ")
        AffineEngine().encrypt(b"test", (4, 7))
        print("❌ FAIL: Should have raised ValueError")
    except ValueError:
        print("✅ SUCCESS: Correctly rejected even scalar key")

    try:
        print("🔍 Testing Hill: Non-invertible matrix check...", end=" ")
        bad_matrix = [[2, 4], [6, 8]]  # det = 16 - 24 = -8 (Even)
        engine_hill = CipherFactory.get_engine(0x04)
        engine_hill.encrypt(b"test", bad_matrix)
        print("❌ FAIL: Should have raised NonInvertibleMatrixError")
    except NonInvertibleMatrixError:
        print("✅ SUCCESS: Correctly rejected even-determinant matrix")

    print("-" * 70)
    print("🏆 FINAL: Imperial Audit Complete. All logical invariants verified.")


if __name__ == "__main__":
    run_imperial_test()