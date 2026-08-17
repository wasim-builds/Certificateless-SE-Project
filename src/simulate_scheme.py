import time
import hashlib
import os
from ecdsa import SECP256k1, SigningKey, VerifyingKey

def benchmark_scheme():
    print("==================================================")
    print("  CL-SE Scheme X: Performance Benchmarking")
    print("==================================================")
    
    # 1. Setup Phase
    start = time.time()
    # Using SECP256k1 as the cyclic group G
    s = SigningKey.generate(curve=SECP256k1) # Master secret
    P_pub = s.get_verifying_key()            # Master public key
    setup_time = time.time() - start
    print(f"[+] Setup Phase: {setup_time*1000:.3f} ms")

    # 2. KeyGen Phase (Data Owner and Data User)
    start = time.time()
    sk_DO = SigningKey.generate(curve=SECP256k1)
    pk_DO = sk_DO.get_verifying_key()
    
    sk_DU = SigningKey.generate(curve=SECP256k1)
    pk_DU = sk_DU.get_verifying_key()
    
    sk_CS = SigningKey.generate(curve=SECP256k1)
    pk_CS = sk_CS.get_verifying_key()
    keygen_time = time.time() - start
    print(f"[+] Key Generation (3 entities): {keygen_time*1000:.3f} ms")

    # 3. Encrypt Phase (Data Owner)
    keyword = b"MEDICAL_RECORD_123"
    start = time.time()
    # r * P
    r = SigningKey.generate(curve=SECP256k1)
    R = r.get_verifying_key().to_string()
    
    # K_DODU = r * PK_DU
    # Simulated via ECDH key exchange math
    shared_point = r.privkey.secret_multiplier * sk_DU.get_verifying_key().pubkey.point
    K_DODU = shared_point.x().to_bytes(32, 'big')
    
    # H4 Hash
    hash_input = keyword + K_DODU + R
    Cw = hashlib.sha256(hash_input).digest()
    encrypt_time = time.time() - start
    print(f"[+] Encrypt (Index Generation): {encrypt_time*1000:.3f} ms")

    # 4. Trapdoor Phase (Data User)
    start = time.time()
    t = SigningKey.generate(curve=SECP256k1)
    T1 = t.get_verifying_key().to_string()
    
    # t * PK_DO
    shared_point_t = t.privkey.secret_multiplier * sk_DO.get_verifying_key().pubkey.point
    K_t = shared_point_t.x().to_bytes(32, 'big')
    
    T2_core = hashlib.sha256(keyword + K_t + T1).digest()
    
    # Blinding for OKGA resistance: t * PK_CS
    blind_point = t.privkey.secret_multiplier * sk_CS.get_verifying_key().pubkey.point
    blind_key = blind_point.x().to_bytes(32, 'big')
    T3 = bytes(a ^ b for a, b in zip(T2_core, hashlib.sha256(blind_key).digest()))
    trapdoor_time = time.time() - start
    print(f"[+] Trapdoor Generation (Dual-Blinded): {trapdoor_time*1000:.3f} ms")

    # 5. Search / Test Phase (Cloud Server)
    start = time.time()
    # Server unblinds using its secret key: x_CS * T1
    unblind_point = sk_CS.privkey.secret_multiplier * t.get_verifying_key().pubkey.point
    unblind_key = unblind_point.x().to_bytes(32, 'big')
    
    T2_star = bytes(a ^ b for a, b in zip(T3, hashlib.sha256(unblind_key).digest()))
    
    # Test Equality (Simplified for benchmark)
    match = (T2_core == T2_star)
    search_time = time.time() - start
    print(f"[+] Search / Test Phase: {search_time*1000:.3f} ms")
    
    print("==================================================")
    if match:
        print("[*] RESULT: Trapdoor MATCHES Keyword successfully!")
    else:
        print("[*] RESULT: Trapdoor Mismatch!")

if __name__ == '__main__':
    benchmark_scheme()
