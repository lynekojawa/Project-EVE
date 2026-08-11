"""
Project EVE v2.1 - phase 1: core cipher engines
Implements Base Cipher, PKCS#7 Padding, Z_256 Modular Cipher Engines and Cipher Factory.
"""
import abc
from typing import List, Tuple, Union

class CryptoError(Exception):
    """Base exception for cryptographic execution failures"""
    pass

class InvalidPaddingError(CryptoError):
    """Raised when PKC#7 padding validation fails"""
    pass
class NonInvertibleMatrixError(CryptoError):
    """Raised when a Hill Cipher matrix key is non-invertible in Z_256."""
    pass

class BaseCipher(abc.ABC):
    """Abstract Base Class for all Z_256 cipher engines with PKCS#7 capabilities."""
    @staticmethod
    def pad(data: bytes, block_size: int) -> bytes:
        """Applies PKCS#7 block padding to arbitrary byte data.
        For data length L and block size n, padding byte value p = n - (L mod n).
        Appends p bytes of value p.
        """

        if block_size <1 or block_size >255:
            raise ValueError("Block size must be in range [1, 255].")
        padding_len = block_size - (len(data) % block_size)
        return data +bytes([padding_len] * padding_len)

    @staticmethod
    def unpad(data: bytes, block_size: int) -> bytes:
        """
        Validates and strips PKCS#7 block padding in constant-time checks where applicable.
        Raises InvalidPaddingError if padding structure is malformed
        """
        if not data:
            raise InvalidPaddingError("Data payload is empty.")
        if len(data) % block_size != 0:
            raise InvalidPaddingError("Payload length is not a multiple of block size.")

        padding_len = data[-1]
        if padding_len < 1 or padding_len > block_size or padding_len > len(data):
            raise InvalidPaddingError("Invalid PKC#7 padding length indicator.")
        for i in range(1, padding_len +1):
            if data[-i] != padding_len:
                raise InvalidPaddingError("Corrupted PKCS#7 padding bytes detected.")
        return data[: -padding_len]

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes, key: Union[int, Tuple[int, int], str, bytes, List[List[int]]]) -> bytes:
        """Encrypts raw bytes under the designated key structure."""
        pass

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes, key: Union[int, Tuple[int, int], str, bytes, List[List[int]]]) -> bytes:
        """Decrypts ciphertext bytes under the designated key structure."""
        pass

class CaesarEngine(BaseCipher):
    """Engine 0x01: Caesar Modular Shift Cipher over Z_256"""
    def encrypt(self, plaintext: bytes, key: int) -> bytes:
        shift = key % 256
        return bytes([(b + shift) % 256 for b in plaintext])

    def decrypt(self, ciphertext: bytes, key: int) -> bytes:
        shift = key % 256
        return bytes([(b - shift) % 256 for b in ciphertext])

class AffineEngine(BaseCipher):
    """
    Engine 0x02: Affine Cipher over Z_256
    Encryption: C = (a * P + b) mod 256
    Decryption: P = (a^-1 * (C-b)) mod 256
    """

    @staticmethod
    def mod_inverse_256(a: int) -> int:
        """
        Computes modular multiplicative inverse of 'a' in Z_256 via Extended Euclidean algorithm.
        Requires gcd(a, 256) == 1, which holds iff 'a' is odd.
        """

        a_mod = a % 256
        if a_mod % 2== 0:
            raise ValueError(f"Scalar key 'a'={a} is even; gcd({a_mod}, 256) != 1. Invertibility fails")

        t, new_t = 0, 1
        r, new_r = 256, a_mod

        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t - quotient * new_t
            r, new_r = new_r, r - quotient * new_r

        if r > 1:
            raise ValueError(f"Scalar {a} has no modular inverse in Z_256")
        if t < 0:
            t += 256
        return t

    def encrypt(self, plaintext: bytes, key: Tuple[int, int]) -> bytes:
        a, b = key
        _ = self.mod_inverse_256(a)
        return bytes([a * p + b] %256 for p in plaintext)

    def decrypt(self, ciphertext: bytes, key: Tuple[int, int]) -> bytes:
        a, b = key
        a_inv = self.mod_inverse_256(a)
        return bytes([(a_inv * (c-b)) %256 for c in ciphertext])

class VigenereEngine(BaseCipher):
    """Engine 0x03: Polyalphabetic Stream Cipher over Z_256."""

    def encrypt(self, plaintext: bytes, key: Union[str, bytes]) -> bytes:
        key_bytes = key.encode('utf-8') if isinstance(key, str) else key
        if not key_bytes:
            raise ValueError("Vigenere key vector cannot be empty")
        k_len = len(key_bytes)
        return bytes([(p + key_bytes[i % k_len]) % 256 for i, p in enumerate(plaintext)])

    def decrypt(self, plaintext: bytes, key: Union[str, bytes]) -> bytes:
        key_bytes = key.encode('utf-8') if isinstance(key, str) else key
        if not key_bytes:
            raise ValueError("Vigenere key vector cannot be empty")
        k_len = len(key_bytes)
        return bytes([(c - key_bytes[i % k_len]) % 256 for i, c in enumerate(plaintext)])

@Hillcipher






