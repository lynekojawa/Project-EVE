"""
Bridges Presentation layer (app.py) to cipher arsenal and protocol_engine.
"""
import json
import secrets
from typing import Tuple, Dict, Any, Optional
from protocol_engine.protocol_engine import WireProtocolEngine, HMACVerificationError, ReplayAttackError, ClockSkewError
from cipher_arsenal.cipher_arsenal import CryptoError

P_HEX = """
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
"""
P = int(P_HEX.replace("\n", "").replace(" ", ""), 16)
G = 2

ENGINE_NAMES: Dict[int, str] = {
            0x01: "Caesar (Z_256)",
            0x02: "Affine (Z_256)",
            0x03: "Vigenère (Z_256)",
            0x04: "Hill 2x2 Matrix (Z_256)"
        }

class CryptoEngine:
    """ Core cryptographic interface preserving legacy signatures and routing v2.1 with protocols."""
    def __init__(self):
        self.p: int = P
        self.g: int = G

    def generate_keypair(self) -> Tuple[int, int]:
        """Generates ElGamal/DH private and public key pair"""
        private_key = secrets.randbelow(self.p - 3) + 2
        public_key = pow(self.g, private_key, self.p)
        return public_key, private_key

    def derive_shared_secret(self, peer_public_key: int, private_key: int)-> int:
        """Computes Diffie-Hillman shared secret: S= (peer_pub)^priv mod P."""
        return pow(peer_public_key, private_key, self.p)

    def apply_caesar(self, text: str, raw_shift: int, decrypt: bool = False) -> str:
        """
        [UI COMPATIBILITY LAYER]
        Caesar for hackers mode. No use in actual protocol.
        """
        shift = (raw_shift % 26)
        if decrypt:
            shift = -shift

        result = []
        for char in text:
            if char.isalpha():
                base = 65 if char.isupper() else 97
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return "".join(result)

    def send_message(self, plaintext: str, recipient_public_key: int, engine_id: int=0x01, key_param: Optional[Any]= None) -> Tuple[str,str]:
        """
        Executes DH exchange, key expansion, and wire protocol packing,
        Returns:
            Tuple[ciphertext_hex (str), key_payload_json (str)]
        """
        try:
            y_ephem = secrets.randbelow(self.p - 3) + 2
            c1 = pow(self.g, y_ephem, self.p)

            shared_secret = pow(recipient_public_key, y_ephem)

            ciphertext_hex = WireProtocolEngine.pack_message(
                plaintext=plaintext,
                engine_id= engine_id,
                key_param=key_param,
                shared_secret_int=shared_secret
            )
            key_payload = json.dumps({"c1": c1})
            return ciphertext_hex, key_payload


        except CryptoError as e:
            raise CryptoError(f"Encryption failed: {e}") from e

        except Exception as e:
            raise RuntimeError(f"Send error: {e}") from e


    def receive_message(
        self,
        ciphertext_hex: str,
        encrypted_key_json: str,
        recipient_private_key: int,
        override_key_param: Optional[Any] = None
    )-> Dict[str, Any]:
        """
        Recovers shared secret, validates HMAC, unmask SSCI checks anti-replay, and decrypts.
        Returns:
            Dict containing decrypted status, telemetry, and plaintext
        """
        try:
            key_data = json.loads(encrypted_key_json)
            c1 = int(key_data['c1'])

            shared_secret = pow(c1, recipient_private_key)

            engine_id, plaintext, timestamp = WireProtocolEngine.unpack_message(
                ciphertext_hex=ciphertext_hex,
                shared_secret_int=shared_secret,
                override_key_param=override_key_param
            )

            return {
                "success": True,
                "plaintext": plaintext,
                "engine_id": engine_id,
                "engine_name": ENGINE_NAMES.get(engine_id, f"Unknown (0x{engine_id:02X})"),
                "timestamp": timestamp,
                "error": None
            }

        except HMACVerificationError as e:
            return {"success": False, "plaintext": None, "error": f"HMAC Signature Mismatch: {e}"}
        except ReplayAttackError as e:
            return {"success": False, "plaintext": None, "error": f"Anti-Replay Violation: {e}"}
        except ClockSkewError as e:
            return {"success": False, "plaintext": None, "error": f"Clock Skew Error: {e}"}
        except CryptoError as e:
            return {"success": False, "plaintext": None, "error": f"Cryptographic Failure: {e}"}
        except Exception as e:
            return {"success": False, "plaintext": None, "error": f"Decryption Protocol Error: {e}"}





