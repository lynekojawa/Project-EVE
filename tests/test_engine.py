from cipher_arsenal.cipher_arsenal import CipherFactory

def run_imperial_test():
    original_message = b"Imperial Protocol v2.1 - Hello PODO!"

    test_configs = {
        0x01: {"name": "Caesar", "key": 42},
        0x02: {"name": "Affine", "key": (15, 7)},
        0x03: {"name": "Vigenere", "key": "GRAPE_POWER"},
        0x04: {"name": "Hill", "key": [[6, 24, 1], [13, 16, 10], [20, 17, 15]]}
    }

    print(f"🚀 Starting Grand Arsenal Audit for: '{original_message.decode()}'\n")
    print("-" * 60)

    all_passed = True
    for engine_id, config in test_configs.items():
        name = config["name"]
        key = config["key"]

        try:
            engine = CipherFactory.get_engine(engine_id)

            ciphertext = engine.encrypt(original_message, key)

            decrypted_message = engine.decrypt(ciphertext, key)

            if original_message != decrypted_message:
                raise ValueError(f"Round-trip failed. Got: {decrypted_message}")

            print(f"✅ [0x{engine_id:02X}] {name:10} : SUCCESS")
            print(f"    └─ Ciphertext(hex): {ciphertext.hex()[:50]}...")

        except Exception as e:
            all_passed = False
            print(f"❌ [0x{engine_id:02X}] {name:10} : FAILED")
            print(f"    └─ Error: {e}")

    if all_passed:
        print("🏆 All engines are operational and algebraically sound!")
    else:
        print("⚠️ One or more engines failed audit.")

if __name__ == "__main__":
    run_imperial_test()