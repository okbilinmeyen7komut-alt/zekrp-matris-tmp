"""manual-tls (alexbers, MIT) kripto yardımcıları: AES-128-GCM, SHA-256/HMAC, HKDF derive_secret, P-256. Ağ kodu yok."""

# in tls 1.3 the version tls 1.2 is sent for better compatibility
LEGACY_TLS_VERSION = b"\x03\x03"
TLS_AES_128_GCM_SHA256 = b"\x13\x01"

CHANGE_CIPHER = b"\x14"
ALERT = b"\x15"
HANDSHAKE = b"\x16"
APPLICATION_DATA = b"\x17"


# BYTE MANIPULATION HELPERS
def bytes_to_num(b):
    return int.from_bytes(b, "big")


def num_to_bytes(num, bytes_len):
    return int.to_bytes(num, bytes_len, "big")


def rotr(num, count):
    return num >> count | num << (32 - count)


def xor(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


# SYMMETRIC CIPHERS
AES_ROUNDS = 10

# AES_SBOX is some permutation of numbers 0-255
AES_SBOX = [
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125,
    250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204,
    52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235,
    39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209,
    0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51,
    133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33,
    16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96,
    129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36,
    92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244,
    234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139,
    138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17,
    105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104,
    65, 153, 45, 15, 176, 84, 187, 22
]


def aes128_expand_key(key):
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

    enc_keys = [[0, 0, 0, 0] for i in range(AES_ROUNDS + 1)]
    enc_keys[0] = [bytes_to_num(key[i:i + 4]) for i in [0, 4, 8, 12]]

    for t in range(1, AES_ROUNDS + 1):
        prev_key = enc_keys[t-1]
        enc_keys[t][0] = ((AES_SBOX[(prev_key[3] >> 8*2) & 0xFF] << 8*3) ^
                          (AES_SBOX[(prev_key[3] >> 8*1) & 0xFF] << 8*2) ^
                          (AES_SBOX[(prev_key[3] >> 8*0) & 0xFF] << 8*1) ^
                          (AES_SBOX[(prev_key[3] >> 8*3) & 0xFF] << 8*0) ^
                          (RCON[t-1] << 8*3) ^ prev_key[0])

        for i in range(1, 4):
            enc_keys[t][i] = enc_keys[t][i-1] ^ prev_key[i]
    return enc_keys


def aes128_encrypt(key, plaintext):
    TWOTIMES = [2*num if 2*num < 256 else 2*num & 0xff ^ 27 for num in range(256)]

    enc_keys = aes128_expand_key(key)

    t = [bytes_to_num(plaintext[4*i:4*i + 4]) ^ enc_keys[0][i] for i in range(4)]
    for r in range(1, AES_ROUNDS):
        t = [[AES_SBOX[(t[(i + 0) % 4] >> 8*3) & 0xFF],
              AES_SBOX[(t[(i + 1) % 4] >> 8*2) & 0xFF],
              AES_SBOX[(t[(i + 2) % 4] >> 8*1) & 0xFF],
              AES_SBOX[(t[(i + 3) % 4] >> 8*0) & 0xFF]] for i in range(4)]

        t = [[c[1] ^ c[2] ^ c[3] ^ TWOTIMES[c[0] ^ c[1]],
              c[0] ^ c[2] ^ c[3] ^ TWOTIMES[c[1] ^ c[2]],
              c[0] ^ c[1] ^ c[3] ^ TWOTIMES[c[2] ^ c[3]],
              c[0] ^ c[1] ^ c[2] ^ TWOTIMES[c[3] ^ c[0]]] for c in t]

        t = [bytes_to_num(t[i]) ^ enc_keys[r][i] for i in range(4)]

    result = [bytes([
        AES_SBOX[(t[(i + 0) % 4] >> 8*3) & 0xFF] ^ (enc_keys[-1][i] >> 8*3) & 0xFF,
        AES_SBOX[(t[(i + 1) % 4] >> 8*2) & 0xFF] ^ (enc_keys[-1][i] >> 8*2) & 0xFF,
        AES_SBOX[(t[(i + 2) % 4] >> 8*1) & 0xFF] ^ (enc_keys[-1][i] >> 8*1) & 0xFF,
        AES_SBOX[(t[(i + 3) % 4] >> 8*0) & 0xFF] ^ (enc_keys[-1][i] >> 8*0) & 0xFF
    ]) for i in range(4)]
    return b"".join(result)


def aes128_ctr_encrypt(key, msg, nonce, counter_start_val):
    BLOCK_SIZE = 16

    ans = []
    counter = counter_start_val
    for s in range(0, len(msg), BLOCK_SIZE):
        chunk = msg[s:s+BLOCK_SIZE]

        chunk_nonce = nonce + num_to_bytes(counter, 4)
        encrypted_chunk_nonce = aes128_encrypt(key, chunk_nonce)

        decrypted_chunk = xor(chunk, encrypted_chunk_nonce)
        ans.append(decrypted_chunk)

        counter += 1
    return b"".join(ans)


def aes128_ctr_decrypt(key, msg, nonce, counter_start_val):
    return aes128_ctr_encrypt(key, msg, nonce, counter_start_val)


def mutliply_blocks(x, y):
    z = 0
    for i in range(128):
        if x & (1 << (127 - i)):
            z ^= y
        y = (y >> 1) ^ (0xe1 << 120) if y & 1 else y >> 1
    return z


def ghash(h, data):
    CHUNK_LEN = 16

    y = 0
    for pos in range(0, len(data), CHUNK_LEN):
        chunk = bytes_to_num(data[pos: pos + CHUNK_LEN])
        y = mutliply_blocks(y ^ chunk, h)
    return y


def calc_pretag(key, encrypted_msg, associated_data):
    v = b"\x00" * (16 * ((len(associated_data) + 15) // 16) - len(associated_data))
    u = b"\x00" * (16 * ((len(encrypted_msg) + 15) // 16) - len(encrypted_msg))

    h = bytes_to_num(aes128_encrypt(key, b"\x00" * 16))
    data = (associated_data + v + encrypted_msg + u +
            num_to_bytes(len(associated_data)*8, 8) + num_to_bytes(len(encrypted_msg)*8, 8))
    return num_to_bytes(ghash(h, data), 16)


def aes128_gcm_decrypt(key, msg, nonce, associated_data):
    TAG_LEN = 16

    encrypted_msg, tag = msg[:-TAG_LEN], msg[-TAG_LEN:]

    pretag = calc_pretag(key, encrypted_msg, associated_data)
    check_tag = aes128_ctr_encrypt(key, pretag, nonce, counter_start_val=1)
    if check_tag != tag:
        raise ValueError("Decrypt error, bad tag")
    return aes128_ctr_decrypt(key, encrypted_msg, nonce, counter_start_val=2)


def aes128_gcm_encrypt(key, msg, nonce, associated_data):
    encrypted_msg = aes128_ctr_encrypt(key, msg, nonce, counter_start_val=2)

    pretag = calc_pretag(key, encrypted_msg, associated_data)
    tag = aes128_ctr_encrypt(key, pretag, nonce, counter_start_val=1)
    return encrypted_msg + tag


# CRYPTOGRAPHIC HASH FUNCTIONS AND MESSAGE AUTHENTICATION CODES
SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def sha256(msg):
    msg += b"\x80" + b"\x00" * ((64-(len(msg) + 1 + 8)) % 64) + num_to_bytes(len(msg)*8, 8)

    ss = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    for pos in range(0, len(msg), 64):
        chunk = msg[pos:pos + 64]

        w = [bytes_to_num(chunk[4*i:4*i+4]) for i in range(16)]
        for i in range(16, 64):
            a = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >> 3)
            b = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((a + b + w[i-16] + w[i-7]) & 0xffffffff)

        s = ss.copy()
        for i in range(64):
            c = (s[4] & s[5]) ^ ((s[4] ^ 0xffffffff) & s[6])
            t = SHA256_K[i] + s[7] + c + w[i] + (rotr(s[4], 6) ^ rotr(s[4], 11) ^ rotr(s[4], 25))
            q = rotr(s[0], 2) ^ rotr(s[0], 13) ^ rotr(s[0], 22)
            m = (s[0] & s[1]) ^ (s[0] & s[2]) ^ (s[1] & s[2])
            s = [(q + m + t) & 0xffffffff, s[0], s[1], s[2], (s[3] + t) & 0xffffffff, s[4], s[5], s[6]]

        ss = [(ss[i] + s[i]) & 0xffffffff for i in range(8)]
    return b"".join(num_to_bytes(a, 4) for a in ss)


def hmac_sha256(key, data):
    BLOCK_SIZE = 512 // 8
    IPAD = b"\x36" * BLOCK_SIZE
    OPAD = b"\x5c" * BLOCK_SIZE

    if len(key) <= BLOCK_SIZE:
        key += b"\x00" * (BLOCK_SIZE - len(key))
    else:
        key = sha256(key)
    return sha256(xor(key, OPAD) + sha256(xor(key, IPAD) + data))


def derive_secret(label, key, data, hash_len):
    full_label = b"tls13 " + label
    packed_data = (num_to_bytes(hash_len, 2) + num_to_bytes(len(full_label), 1) +
                   full_label + num_to_bytes(len(data), 1) + data)

    secret = bytearray()
    i = 1
    while len(secret) < hash_len:
        secret += hmac_sha256(key, secret[-32:] + packed_data + num_to_bytes(i, 1))
        i += 1
    return bytes(secret[:hash_len])


# ELLIPTIC CURVE FUNCTIONS
def egcd(a, b):
    if a == 0:
        return 0, 1
    y, x = egcd(b % a, a)
    return x - (b // a) * y, y


def mod_inv(a, p):
    return egcd(a, p)[0] if a >= 0 else p - egcd(-a, p)[0]


def add_two_ec_points(p1_x, p1_y, p2_x, p2_y, a, p):
    if p1_x == p2_x and p1_y == p2_y:
        s = (3*p1_x*p1_x + a) * mod_inv(2*p2_y, p)
    elif p1_x != p2_x:
        s = (p1_y - p2_y) * mod_inv(p1_x - p2_x, p)
    else:
        raise NotImplementedError

    x = s*s - p1_x - p2_x
    y = -p1_y + s*(p1_x - x)
    return x % p, y % p


def multiply_num_on_ec_point(num, g_x, g_y, a, p):
    x, y = None, None
    while num:
        if num & 1:
            x, y = add_two_ec_points(x, y, g_x, g_y, a, p) if x else (g_x, g_y)
        g_x, g_y = add_two_ec_points(g_x, g_y, g_x, g_y, a, p)
        num >>= 1
    return x, y


# AUTHENTIATED ENCRYPTION HELPERS
def do_authenticated_encryption(key, nonce_base, seq_num, msg_type, payload):
    TAG_LEN = 16

    payload += msg_type
    nonce = xor(nonce_base, num_to_bytes(seq_num, 12))
    data = APPLICATION_DATA + LEGACY_TLS_VERSION + num_to_bytes(len(payload)+TAG_LEN, 2)

    encrypted_msg = aes128_gcm_encrypt(key, payload, nonce, associated_data=data)
    return encrypted_msg


def do_authenticated_decryption(key, nonce_start, seq_num, msg_type, payload):
    nonce = xor(nonce_start, num_to_bytes(seq_num, 12))

    data = msg_type + LEGACY_TLS_VERSION + num_to_bytes(len(payload), 2)
    msg = aes128_gcm_decrypt(key, payload, nonce, associated_data=data)

    msg_type, msg_data = msg[-1:], msg[:-1]
    return msg_type, msg_data


SECP256R1_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
SECP256R1_A = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
SECP256R1_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
               0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
