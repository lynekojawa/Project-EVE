#Today(5/12) We are continuing Project Eve and I am hoping to get phase 1 done.
#Goal: Update Iterative GCD for make it more efficient
#the recursion is mathematically right however python has default recursion limit, so in this case iterative is better.
import sympy
import secrets
import unicodedata

#RFC3526 - 1536 bit safe prime
P_Hex =""" 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
            29024E088A67CC74020BBEA63B139B22514A08798E3404DDE
            F9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E4
            85B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE3
            86BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC200
            7CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655
            D23DCA3AD961C62F356208552BB9ED529077096966D670C35
            4E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772
            C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6
            955817183995497CEA956AE515D2261898FA051015728E5A8
            AACAA68FFFFFFFFFFFFFFFF"""
P = int(P_Hex.replace("\n", "").replace(" ",""), 16)
G = 2

class CryptoEngine:
    def __init__(self, bit_length = 1536):
        self.p = P

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



engine = CryptoEngine()
a = 11
m = 3
inverse = engine.mod_inverse(a,m)
print(f"Modular inverse {a} of {m} is {inverse}")
print(f"Verification: ({a}*{inverse}) % {m} = {(a * inverse) % m}")