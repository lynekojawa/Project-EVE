#Today(4/30) we are starting my 4th project that is fun crypto coding project, let's see if I can progress phase 1
#easier than last three projects!

import sympy
import secrets
import unicodedata

#RFC3526 - 1536 bit safe prime
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1 \
    29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
G = 2

class CryptoEngine:
    def __init__(self, bit_length = 128):
        self.p = P

    def extended_gcd(a,b):
        if b == 0:
            return a, 1, 0
        else:
            g, x_next, y_next = self.extended_gcd(b, a % b)
            x = y_next
            y = x_next - (a // b) * y_next
            return g, x, y

    def mod_inverse(self, a, m):
        g, x, y = self.extended_gcd(a,m)
        if g != 1:
            raise ValueError("modular inverse does not exist")
        else:
            result = (x % m+ m) % m
            return result