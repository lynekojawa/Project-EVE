#Today(5/13) We are moving to finish cryptoEngine, and hopefully move forward.

import sympy
import secrets
import unicodedata

#RFC3526 - 1536 bit safe prime
P_Hex ="""
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
        """

P = int(P_Hex.replace("\n", "").replace(" ",""), 16)
G = 2

class CryptoEngine:
    def __init__(self, bit_length = 1536):
        self.p = P
        self.g = G

    def extended_gcd(self, a,b):
        old_r, r = a, b
        old_s, s = 1, 0
        old_t, t = 0, 1
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t
        return old_r, old_s, old_t

    def mod_inverse(self, a, m):
        gcd, x, y = self.extended_gcd(a,m)
        if gcd != 1:
            raise ValueError("modular inverse does not exist")
        else:
            result = (x % m + m) % m
            return result

    def generate_keypair(self):
        private_key = secrets.randbelow(self.p - 3) + 2
        public_key = pow(self.g, private_key, self.p)
        return public_key, private_key

    def encrypt_key(self, session_shift, public_key):
        key_y = secrets.randbelow(self.p - 3) + 2
        c1 = pow(self.g, key_y, self.p)
        shared_message = pow(public_key, key_y, self.p)
        c2 = (session_shift * shared_message) % self.p
        return c1, c2

    def decrypt_key(self, c1, c2, private_key):
        shared_message = pow(c1, private_key, self.p)
        s_inv = self.mod_inverse(shared_message, self.p)
        session_shift = (c2 * s_inv) % self.p
        return session_shift

#Test
if __name__ == "__main__":
    engine = CryptoEngine()

    pub_key, priv_key = engine.generate_keypair()

    print(f"---ElGamal Key Generation Test ---")

    my_secret_code = 42
    c1, c2 = engine.encrypt_key(my_secret_code, pub_key)
    decrypted_code = engine.decrypt_key(c1, c2, priv_key)

    print(f"Original: {my_secret_code}")
    print(f"Decrypted: {decrypted_code}")

    assert my_secret_code == decrypted_code
    print("Success")