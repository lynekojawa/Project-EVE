"""
Project EVE v2.1 - phase 1: core cipher engines
Implements Base Cipher, PKCS#7 Padding, Z_256 Modular Cipher Engines and Cipher Factory.
Updates:
1. Separated Block/Stream logic.
2. Eliminated redundant matrix inversions.
3. Injected modular reductions into determinant recursion.
"""
import abc
from typing import List, Tuple, Union

class CryptoError(Exception):
    """Base exception for cryptographic execution failures"""
    pass

class InvalidPaddingError(CryptoError):
    """Raised when PKCS#7 padding validation fails"""
    pass

class NonInvertibleMatrixError(CryptoError):
    """Raised when a Hill Cipher matrix key is non-invertible in Z_256."""
    pass

class PKCS7:
    """Utility class for PKCS#7 padding. Separated from BaseCipher to prevent inheritance pollution."""
    @staticmethod
    def pad(data: bytes, block_size: int) -> bytes:
        if block_size < 1 or block_size > 255:
            raise ValueError("Block size must be in range [1, 255].")
        padding_len = block_size - (len(data) % block_size)
        return data + bytes([padding_len] * padding_len)

    @staticmethod
    def unpad(data: bytes, block_size: int) -> bytes:
        """Validates and strips PKCS#7 padding."""
        if block_size < 1 or block_size > 255:
            raise ValueError("Block size must be in range [1, 255].")

        if not data:
            raise InvalidPaddingError("Data payload is empty.")

        if len(data) % block_size != 0:
            raise InvalidPaddingError("Payload length is not a multiple of block size.")

        padding_len = data[-1]
        if padding_len < 1 or padding_len > block_size or padding_len > len(data):
            raise InvalidPaddingError("Invalid PKCS#7 padding length indicator.")

        for i in range(1, padding_len + 1):
            if data[-i] != padding_len:
                raise InvalidPaddingError("Corrupted PKCS#7 padding bytes detected.")

        return data[:-padding_len]


class BaseCipher(abc.ABC):
    """Abstract Base Class for all Z_256 cipher engines"""

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes, key: Union[int, Tuple[int, int], str, bytes, List[List[int]]]) -> bytes:
        pass

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes, key: Union[int, Tuple[int, int], str, bytes, List[List[int]]]) -> bytes:
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
        a, b = key[0] % 256, key[1] % 256
        self.mod_inverse_256(a)
        return bytes([(a * p + b) % 256 for p in plaintext])

    def decrypt(self, ciphertext: bytes, key: Tuple[int, int]) -> bytes:
        a, b = key[0] % 256, key[1] % 256
        a_inv = self.mod_inverse_256(a)
        return bytes([(a_inv * (c - b)) % 256 for c in ciphertext])

class VigenereEngine(BaseCipher):
    """Engine 0x03: Polyalphabetic Stream Cipher over Z_256."""

    def encrypt(self, plaintext: bytes, key: Union[str, bytes]) -> bytes:
        key_bytes = key.encode('utf-8') if isinstance(key, str) else key
        if not key_bytes:
            raise ValueError("Vigenere key vector cannot be empty")
        k_len = len(key_bytes)
        return bytes([(p + key_bytes[i % k_len]) % 256 for i, p in enumerate(plaintext)])

    def decrypt(self, ciphertext: bytes, key: Union[str, bytes]) -> bytes:
        key_bytes = key.encode('utf-8') if isinstance(key, str) else key
        if not key_bytes:
            raise ValueError("Vigenere key vector cannot be empty")
        k_len = len(key_bytes)
        return bytes([(c - key_bytes[i % k_len]) % 256 for i, c in enumerate(ciphertext)])

class HillEngine(BaseCipher):
    """
    Engine 0x04: High-Density n x n Matrix Hill Cipher over Z_256 ring.
    Requires PKCS#7 block padding
    """
    @staticmethod
    def matrix_det(matrix: List[List[int]]) -> int:
        n = len(matrix)
        if n == 1:
            return matrix[0][0]
        if n == 2:
            return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]

        det = 0
        for j in range(n):
            submatrix = [row[:j] + row[j + 1:] for row in matrix[1:]]
            sign = 1 if j % 2 == 0 else -1
            det += sign * matrix[0][j] * HillEngine.matrix_det(submatrix)
        return det

    @staticmethod
    def matrix_minor(matrix: List[List[int]], i: int, j: int) -> List[List[int]]:
        return [row[:j] + row[j + 1:] for row in (matrix[:i] + matrix[i + 1:])]

    @staticmethod
    def invert_key_matrix(matrix: List[List[int]]) -> List[List[int]]:
        """
        Inverts an n x n key matrix over ring Z_256 using the Adjugate Matrix method.
        Algebraic Guard: Invertible in Z_256 iff gcd(det(K), 256) == 1 (det(K) is odd).
        """

        n = len(matrix)
        for row in matrix:
            if len(row) != n: raise ValueError("Key matrix must be square (n x n).")

        det = HillEngine.matrix_det(matrix)

        det_mod = det % 256

        if det_mod % 2 == 0:
            raise NonInvertibleMatrixError(f"det(K) = {det} (mod 256 = {det_mod}) is even.")

        det_inv = AffineEngine.mod_inverse_256(det_mod)

        if n == 1: return [[det_inv]]
        adjugate = [[0] * n for _ in range(n)]

        for i in range(n):
            for j in range(n):
                minor = HillEngine.matrix_minor(matrix, i, j)
                cofactor = ((-1) ** (i + j)) * HillEngine.matrix_det(minor)
                adjugate[j][i] = cofactor % 256
        inv_matrix = [[(det_inv * adjugate[i][j]) % 256 for j in range(n)] for i in range(n)]
        return inv_matrix


    def encrypt(self, plaintext: bytes, key: List[List[int]]) -> bytes:
        n = len(key)
        if HillEngine.matrix_det(key) % 2 == 0:
            raise NonInvertibleMatrixError("Key matrix is not invertible.")

        p = PKCS7.pad(plaintext, block_size=n)
        res = []
        for offset in range(0, len(p), n):
            block = p[offset:offset + n]
            for i in range(n):
                c_byte = sum(key[i][j] * block[j] for j in range(n)) % 256
                res.append(c_byte)
        return bytes(res)

    def decrypt(self, ciphertext: bytes, key: List[List[int]]) -> bytes:
        n = len(key)
        if n < 1:
            raise ValueError("Key matrix must not be empty.")

        if len(ciphertext) % n != 0:
            raise InvalidPaddingError(
                "Ciphertext payload length is not aligned to Hill block size."
            )
        inv = self.invert_key_matrix(key) # Full inversion only needed here
        res = []
        for o in range(0, len(ciphertext), n):
            block = ciphertext[o:o+n]
            for i in range(n):
                res.append(sum(inv[i][j] * block[j] for j in range(n)) % 256)
        return PKCS7.unpad(bytes(res), n)

class CipherFactory:
    """Factory interface for instantiating Z_256 modular cipher engines."""

    _ENGINES = {
        0x01: CaesarEngine,
        0x02: AffineEngine,
        0x03: VigenereEngine,
        0x04: HillEngine
    }

    @classmethod
    def get_engine(cls, engine_id: int) -> BaseCipher:
        """Returns instantiated cipher engine for give 1-byte ID."""
        if engine_id not in cls._ENGINES:
            raise ValueError(f"Unsupported Engine Identifier: 0x{engine_id: 02X}")
        return cls._ENGINES[engine_id]()















