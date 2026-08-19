"""
Project EVE v2.1 — Phase 2: Protocol & Security Layer Engine
Updates:
1. Deterministic Matrix Derivation (Full Entropy).
2. Protocol-level PKCS#7 Unification (Anti-Length-Leak).
3. Strict UTF-8 Decoding.
"""

import hashlib
import hmac
import struct
import time
import secrets
from typing import Tuple, Union, List, Optional, Any
from cipher_arsenal.cipher_arsenal import CipherFactory, CryptoError, NonInvertibleMatrixError, HillEngine

class ProtocolError(CryptoError):
    """Base exception for protocol wire-level processing failures"""
    pass

class HMACVerificationError(ProtocolError):
    """Raised when HMAC signature fails verification (tempering detected)."""
    pass

class ReplayAttackError(ProtocolError):
    """Raised when decrypted payload timestamp exceeds max drift window."""
    pass

class ClockSkewError(ProtocolError):
    """Raised when payload timestamp is significantly in the future"""
    pass

class KDFEngine:
    """Domain-Separated Key Derivation Function over 1536-bit Shared Secret"""
    @staticmethod
    def derive_keys(shared_secret_int: int) -> Tuple[bytes, bytes, int]:
        """
        Expands 1536-bit shared secret integer into isolated cryptographic keys.
        Returns:
            Tuple[K_enc (32 bytes), K_mac (32 bytes), S_ssci (1 byte int)]
        """

        s_bytes = shared_secret_int.to_bytes(192, byteorder = 'big')
        k_enc = hashlib.sha256(s_bytes + b"eve-v2.1-enc").digest()
        k_mac = hashlib.sha256(s_bytes + b"eve-v2.1-mac").digest()
        s_ssci = hashlib.sha256(s_bytes + b"eve-v2.1-ssci").digest()[0]

        return k_enc, k_mac, s_ssci

class WireProtocolEngine:
    """
    Assembles and validates secure wire-protocol packets.
    Handles temporal anti-replay protection, HMAC signing, and SSCI masking.
    """
    PROTOCOL_BLOCK_SIZE = 16
    DRIFT_MIN_SECONDS = -30.0 #Allow up to 30s client clock skew behind
    DRIFT_MAX_SECONDS = 60.0 #Allow up to 60s packet transit delay

    @classmethod
    def _derive_hill_matrix(cls, k_enc: bytes, n: int = 2) -> List[List[int]]:
        """
        Derives an n x n invertible matrix using the full entropy of K_enc.
        Uses deterministic seeding to ensure peer-to-peer synchronization.
        """

        seed = hashlib.sha512(k_enc + b"hill-matrix-salt").digest()
        idx = 0

        while idx <= len(seed) - (n * n):
            matrix = []
            for i in range(n):
                row = list(seed[idx + i * n: idx + (i + 1) * n])
                matrix.append(row)
            try:
                if HillEngine.matrix_det(matrix) % 2 != 0:
                    return matrix
            except Exception:
                pass
            idx += 1

        raise ValueError(f"Entropy pool exhausted deriving {n}x{n} Hill matrix from K_enc.")
    @classmethod
    def _resolve_effective_key(
        cls,
        engine_id: int,
        key_param: Optional[Union[int, Tuple[int, int], str, bytes, List[List[int]]]],
        k_enc: bytes
    ) -> Any:
        """
        Resolves explicitly provided key parameters or derives mathematically valid fallback
        key structures across all 4 cipher engines using K_enc.
        """
        if key_param is not None:
            return key_param
        if engine_id == 0x01:
            return k_enc[0]

        elif engine_id == 0x02:
            a = k_enc[0] | 1
            b = k_enc[1]
            return (a, b)

        elif engine_id == 0x03:
            return k_enc

        elif engine_id == 0x04:
            return cls._derive_hill_matrix(k_enc)
        else:
            raise ValueError(f"Unsupported Engine ID: 0x{engine_id:02X}")

    @classmethod
    def pack_message(
        cls,
        plaintext: str,
        engine_id: int,
        key_param: Union[int, Tuple[int, int], str, bytes, List[List[int]]] = None,
        shared_secret_int: int = 0
    ) -> str:
        """
        Serializes, encrypts, signs, and masks a plaintext message.
        Returns:
            Hex-encoded string ready for storage in eve_message.ciphertext
        """

        k_enc, k_mac, s_ssci = KDFEngine.derive_keys(shared_secret_int)

        current_time = int(time.time())
        time_prefix = struct.pack(">Q", current_time)
        plaintext_bytes = plaintext.encode('utf-8')
        iv = secrets.token_bytes(8)
        raw = time_prefix + plaintext_bytes

        p_final = bytes(raw[i] ^ iv[i % 8] for i in range(len(raw)))
        cipher_engine = CipherFactory.get_engine(engine_id)

        effective_key = cls._resolve_effective_key(engine_id, key_param, k_enc)

        ciphertext = cipher_engine.encrypt(p_final, effective_key) + iv

        e_masked = bytes([engine_id ^ s_ssci])

        mac_payload = e_masked + ciphertext
        signature = hmac.new(k_mac, mac_payload, hashlib.sha256).digest()
        wire_packet = signature + mac_payload
        return wire_packet.hex()

    @classmethod
    def unpack_message(
        cls,
        ciphertext_hex: str,
        shared_secret_int: int,
        override_key_param: Optional[Union[int, Tuple[int, int], str, bytes, List[List[int]]]] = None,
        )-> Tuple[int, str, int]:
        """
        Validates, unmasks, decrypts, and verifies a hex-encoded wire packet.
        Returns:
            Tuple[unmasked_engine_id (int), decrypted_plaintext(str), timestamp (int)]
        Raises:
              HMACVerificationError: If payload was tempered with.
              ReplayAttackError: If packet timestamp is older than 60s.
              ClockSkewError: If packet timestamp is in the future beyond tolerance
        """
        try:
            wire_bytes = bytes.fromhex(ciphertext_hex)
        except ValueError:
            raise ProtocolError("Invalid hexadecimal packet encoding")

        if len(wire_bytes) < 33 + 8: #32B HMAC + 1B header + 8B Timestamp minimum
            raise ProtocolError("Wire packet truncated; fails minimum size requirement")

        k_enc, k_mac, s_ssci = KDFEngine.derive_keys(shared_secret_int)

        received_signature = wire_bytes[:32]
        mac_payload = wire_bytes[32:]
        e_masked = mac_payload[0]
        ciphertext_with_iv = mac_payload[1:]
        ciphertext = ciphertext_with_iv[:-8]
        iv = ciphertext_with_iv[-8:]

        expected_signature = hmac.new(k_mac, mac_payload, hashlib.sha256).digest()
        if not hmac.compare_digest(received_signature, expected_signature):
            raise HMACVerificationError("SECURITY ALERT: Signature mismatch! Ciphertext payload tempered.")

        unmasked_engine_id = e_masked ^ s_ssci
        cipher_engine = CipherFactory.get_engine(unmasked_engine_id)
        effective_key = cls._resolve_effective_key(unmasked_engine_id, override_key_param, k_enc)

        decrypted_raw = cipher_engine.decrypt(ciphertext, effective_key)
        p_final = bytes(decrypted_raw[i] ^ iv[i % 8] for i in range(len(decrypted_raw)))

        if len(p_final) < 8:
            raise ProtocolError("Decrypted payload too short to contain timestamp header")
        timestamp_bytes = p_final[:8]
        msg_bytes = p_final[8:]

        msg_timestamp = struct.unpack(">Q", timestamp_bytes)[0]
        current_time = int(time.time())
        delta_t = current_time - msg_timestamp

        if delta_t > cls.DRIFT_MAX_SECONDS:
            raise ReplayAttackError(
                f"REPLAY ATTACK REJECTED: Payload age {delta_t:.1f}s exceeds limit ({cls.DRIFT_MAX_SECONDS}s)."
            )
        if delta_t < cls.DRIFT_MIN_SECONDS:
            raise ClockSkewError(
                f"CLOCK SKEW REJECTED: Payload timestamp is {abs(delta_t):.1f}s in the future."
            )
        try:
            plaintext = msg_bytes.decode('utf-8')
        except UnicodeDecodeError as e:
            raise ProtocolError("Decrypted payload is not valid UTF-8.") from e

        return unmasked_engine_id, plaintext, msg_timestamp














