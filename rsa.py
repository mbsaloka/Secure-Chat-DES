import random
import math
from hash import sha256

# Miller-Rabin primality test
def _is_probable_prime(n, k=10):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d * 2^s
    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generate_prime(bits=256):
    """Generate a probable prime of `bits` bits using Miller-Rabin."""
    assert bits >= 8
    while True:
        # generate odd candidate with top bit set
        candidate = random.getrandbits(bits) | (1 << (bits-1)) | 1
        if _is_probable_prime(candidate):
            return candidate

# Extended Euclid & modinv
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

# Key generation
def generate_keypair(bits=512):
    """
    Generate RSA keypair.
    bits = size of each prime p,q. modulus n will be ~2*bits bits.
    For reasonable speed in exercises, bits=512 gives 1024-bit modulus.
    """
    # choose e
    e = 65537
    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            return (e, n), (d, n)

# Encrypt / Decrypt (fixed-length)
def _modulus_byte_length(n):
    return (n.bit_length() + 7) // 8

def rsa_encrypt(message: bytes, pubkey: tuple) -> bytes:
    """
    message: bytes (must be shorter than modulus in integer)
    pubkey: (e, n)
    returns ciphertext as fixed-length bytes = k where k = len(n in bytes)
    """
    e, n = pubkey
    k = _modulus_byte_length(n)
    m_int = int.from_bytes(message, "big")
    if m_int >= n:
        raise ValueError("message too large for the modulus")
    c_int = pow(m_int, e, n)
    return c_int.to_bytes(k, "big")

def rsa_decrypt(ciphertext: bytes, privkey: tuple) -> bytes:
    """
    ciphertext: bytes length k (k may be padded)
    privkey: (d, n)
    returns plaintext as bytes of length <= k; leading zeros may be present
    """
    d, n = privkey
    k = _modulus_byte_length(n)
    if len(ciphertext) != k:
        # pad left with zeros if needed
        ciphertext = ciphertext.rjust(k, b'\x00')
    c_int = int.from_bytes(ciphertext, "big")
    m_int = pow(c_int, d, n)
    return m_int.to_bytes(k, "big")

# Serialization helpers for sending public key over socket
def serialize_public(pubkey: tuple) -> bytes:
    e, n = pubkey
    return f"{e},{n}".encode()

def deserialize_public(data: bytes) -> tuple:
    s = data.decode()
    e_str, n_str = s.split(",", 1)
    return (int(e_str), int(n_str))

# Signing and verification
def rsa_sign(message: bytes, privkey: tuple) -> bytes:
    d, n = privkey
    h = int.from_bytes(sha256(message), 'big')
    sig = pow(h, d, n)
    k = (n.bit_length() + 7) // 8
    return sig.to_bytes(k, 'big')

def rsa_verify(message: bytes, signature: bytes, pubkey: tuple) -> bool:
    e, n = pubkey
    sig_int = int.from_bytes(signature, 'big')
    h_from_sig = pow(sig_int, e, n)
    h_actual = int.from_bytes(sha256(message), 'big')
    return h_from_sig == h_actual
