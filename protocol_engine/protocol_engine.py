"""
Project EVE v2.1 — Phase 2: Protocol & Security Layer Engine
Implements Key Derivation Functions (KDF), HMAC Integrity Verification,
Shared-Secret Cipher Identification (SSCI) Masking, and Anti-Replay Temporal Validation.
"""

import hashlib
import hmac
import struct
import time
from typing import Tuple, Union, List
from cipher_arsenal.cipher_arsenal import CipherFactory, BaseCipher, CryptoError

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
        k_enc = hashlib.sha256(s_bytes + b"eve-v2.1-end").digest()
        k_mac = hashlib.sha256(s_bytes + b"eve-v2.1-mac").digest()
        s_ssci = hashlib.sha256(s_bytes + b"eve-v2.1-ssci").digest()[0]

        return k_enc, k_mac, s_ssci

class WireProtocolEngine:
    """
    Assembles and validates secure wire-protocol packets.
    Handles temporal anti-replay protection, HMAC signing, and SSCI masking.
    """

    DRIFT_MIN_SECONDS = -30.0 #Allow up to 30s client clock skew behind
    DRIFT_MAX_SECONDS = 60.0 #Allow up to 60s packet transit delay

    @classmethod
    def pack_message(
        cls,
        plaintext: str,
        engine_id: int,
        key_param: Union[int, Tuple[int, int], str, bytes, List[List[int]]],
        shared_secret_int: int
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
        p_final = time_prefix + plaintext_bytes

        cipher_engine = CipherFactory.get_engine(engine_id)

        if engine_id == 0x01:
            effective_key = key_param if key_param is not None else k_enc[0]
        elif














