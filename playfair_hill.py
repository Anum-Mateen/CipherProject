from typing import List, Tuple, Dict
import argparse
import hashlib
import secrets
import sys

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_NO_J = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # for Playfair table

# ----------------------------
# Playfair implementation
# ----------------------------
def build_playfair_table(keyword: str) -> Tuple[List[List[str]], Dict[str, Tuple[int,int]]]:
    kw = "".join([c for c in keyword.upper() if c.isalpha()])
    kw = kw.replace("J", "I")
    seen = []
    for ch in kw:
        if ch not in seen:
            seen.append(ch)
    for ch in ALPHA_NO_J:
        if ch not in seen:
            seen.append(ch)
    table = [seen[i*5:(i+1)*5] for i in range(5)]
    pos = {table[r][c]: (r, c) for r in range(5) for c in range(5)}
    return table, pos

def playfair_preprocess(plaintext: str) -> List[str]:
    s = "".join([c for c in plaintext.upper() if c.isalpha()])
    s = s.replace("J", "I")
    pairs = []
    i = 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else 'X'
        if a == b:
            pairs.append(a + 'X')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    if len(pairs) and len(pairs[-1]) == 1:
        pairs[-1] += 'X'
    return pairs

def playfair_encrypt_pair(pair: str, table: List[List[str]], pos: dict) -> str:
    a, b = pair[0], pair[1]
    ra, ca = pos[a]
    rb, cb = pos[b]
    if ra == rb:
        return table[ra][(ca+1) % 5] + table[rb][(cb+1) % 5]
    if ca == cb:
        return table[(ra+1) % 5][ca] + table[(rb+1) % 5][cb]
    return table[ra][cb] + table[rb][ca]

def playfair_decrypt_pair(pair: str, table: List[List[str]], pos: dict) -> str:
    a, b = pair[0], pair[1]
    ra, ca = pos[a]
    rb, cb = pos[b]
    if ra == rb:
        return table[ra][(ca-1) % 5] + table[rb][(cb-1) % 5]
    if ca == cb:
        return table[(ra-1) % 5][ca] + table[(rb-1) % 5][cb]
    return table[ra][cb] + table[rb][ca]

def playfair_encrypt(plaintext: str, keyword: str) -> str:
    table, pos = build_playfair_table(keyword)
    pairs = playfair_preprocess(plaintext)
    return "".join(playfair_encrypt_pair(p, table, pos) for p in pairs)

def playfair_decrypt(ciphertext: str, keyword: str) -> str:
    table, pos = build_playfair_table(keyword)
    pairs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    raw = "".join(playfair_decrypt_pair(p, table, pos) for p in pairs)

    cleaned = []
    i = 0
    while i < len(raw):
        if i+2 < len(raw) and raw[i] == raw[i+2] and raw[i+1] == 'X':
            cleaned.append(raw[i])
            cleaned.append(raw[i+2])
            i += 3
        else:
            cleaned.append(raw[i])
            i += 1
    result = "".join(cleaned)
    if result.endswith('X'):
        result = result[:-1]
    return result

# ----------------------------
# Hill 3x3 implementation
# ----------------------------
def letters_to_vec(s: str) -> List[int]:
    return [ord(c) - 65 for c in s]

def vec_to_letters(v: List[int]) -> str:
    return "".join(chr((x % 26) + 65) for x in v)

def mat_mul_mod26(A: List[List[int]], v: List[int]) -> List[int]:
    n = len(A)
    return [sum(A[i][j] * v[j] for j in range(n)) % 26 for i in range(n)]

def det_3x3(M: List[List[int]]) -> int:
    a,b,c = M[0]; d,e,f = M[1]; g,h,i = M[2]
    return (a*(e*i - f*h) - b*(d*i - f*g) + c*(d*h - e*g)) % 26

def egcd(a: int, b: int):
    if b == 0:
        return (1, 0, a)
    x1, y1, g = egcd(b, a % b)
    return (y1, x1 - (a // b) * y1, g)

def modinv(a: int, m: int) -> int:
    a = a % m
    x, y, g = egcd(a, m)
    if g != 1:
        raise ValueError(f"No modular inverse for {a} mod {m}")
    return x % m

def matrix_inverse_mod26_3x3(M: List[List[int]]) -> List[List[int]]:
    det = det_3x3(M)
    inv_det = modinv(det, 26)
    a,b,c = M[0]; d,e,f = M[1]; g,h,i = M[2]
    adj = [
        [(e*i - f*h) % 26, (c*h - b*i) % 26, (b*f - c*e) % 26],
        [(f*g - d*i) % 26, (a*i - c*g) % 26, (c*d - a*f) % 26],
        [(d*h - e*g) % 26, (b*g - a*h) % 26, (a*e - b*d) % 26]
    ]
    return [[(inv_det * adj[r][c]) % 26 for c in range(3)] for r in range(3)]

def hill_encrypt(playfair_text: str, K: List[List[int]]) -> str:
    s = playfair_text
    if len(s) % 3 != 0:
        s += 'X' * (3 - (len(s) % 3))
    ct_blocks = []
    for i in range(0, len(s), 3):
        v = letters_to_vec(s[i:i+3])
        cvec = mat_mul_mod26(K, v)
        ct_blocks.append(vec_to_letters(cvec))
    return "".join(ct_blocks)

def hill_decrypt(ciphertext: str, Kinv: List[List[int]]) -> str:
    s = ciphertext
    pt_blocks = []
    for i in range(0, len(s), 3):
        v = letters_to_vec(s[i:i+3])
        pvec = mat_mul_mod26(Kinv, v)
        pt_blocks.append(vec_to_letters(pvec))
    return "".join(pt_blocks)

# ----------------------------
# Combined pipeline
# ----------------------------
def encrypt(plaintext: str, playfair_kw: str, K: List[List[int]]) -> str:
    if len("".join([c for c in playfair_kw if c.isalpha()])) < 10:
        raise ValueError("Playfair keyword must contain at least 10 alphabetic characters (assignment requirement)")
    pf_out = playfair_encrypt(plaintext, playfair_kw)
    ct = hill_encrypt(pf_out, K)
    return ct

def decrypt(ciphertext: str, playfair_kw: str, K: List[List[int]]) -> str:
    Kinv = matrix_inverse_mod26_3x3(K)
    pre_pf = hill_decrypt(ciphertext, Kinv)
    pt = playfair_decrypt(pre_pf, playfair_kw)
    return pt

# ----------------------------
# Key helpers
# ----------------------------
def build_hill_from_passphrase(passphrase: str, max_tries: int = 1000) -> Tuple[List[List[int]], int]:
    base = passphrase.encode('utf-8')
    for ctr in range(max_tries):
        blob = hashlib.sha256(base + ctr.to_bytes(2, 'big')).digest()
        M = [[blob[i*3 + j] % 26 for j in range(3)] for i in range(3)]
        det = det_3x3(M)
        if det % 2 != 0 and det % 13 != 0:
            return M, ctr
    raise ValueError("Could not find invertible Hill matrix from passphrase within tries")

def random_hill_matrix() -> List[List[int]]:
    while True:
        M = [[secrets.randbelow(26) for _ in range(3)] for _ in range(3)]
        det = det_3x3(M)
        if det % 2 != 0 and det % 13 != 0:
            return M

# ----------------------------
# Known-plaintext attack helper
# ----------------------------
def derive_hill_from_known_pairs(plain_intermediate: str, cipher_text: str) -> List[List[int]]:
    if len(plain_intermediate) < 9 or len(plain_intermediate) % 3 != 0:
        raise ValueError("plain_intermediate must be a multiple of 3 and at least 9 letters")
    if len(plain_intermediate) != len(cipher_text):
        raise ValueError("Lengths must match")
    P_blocks = [plain_intermediate[i:i+3] for i in range(0, 9, 3)]
    C_blocks = [cipher_text[i:i+3] for i in range(0, 9, 3)]
    P = [[letters_to_vec(b)[r] for b in P_blocks] for r in range(3)]
    C = [[letters_to_vec(b)[r] for b in C_blocks] for r in range(3)]
    Pmat = [[P[r][c] for c in range(3)] for r in range(3)]
    Cmat = [[C[r][c] for c in range(3)] for r in range(3)]
    Pinv = matrix_inverse_mod26_3x3(Pmat)
    K = [[sum(Cmat[r][k] * Pinv[k][c] for k in range(3)) % 26 for c in range(3)] for r in range(3)]
    return K

def derive_hill_from_visible_plaintext(visible_plain: str, cipher_text: str, playfair_kw: str) -> List[List[int]]:
    intermediate = playfair_encrypt(visible_plain, playfair_kw)
    if len(intermediate) != len(cipher_text):
        raise ValueError("Intermediate length from Playfair does not match provided ciphertext length.")
    return derive_hill_from_known_pairs(intermediate, cipher_text)

# ----------------------------
# Small utilities
# ----------------------------
def parse_matrix_arg(s: str) -> List[List[int]]:
    rows = s.split(';')
    if len(rows) != 3:
        raise argparse.ArgumentTypeError("Matrix must have 3 rows separated by ';'")
    M = []
    for r in rows:
        cells = [int(x) for x in r.split(',')]
        if len(cells) != 3:
            raise argparse.ArgumentTypeError("Each row needs 3 integers separated by ','")
        M.append(cells)
    return M

def matrix_to_str(M: List[List[int]]) -> str:
    return '\n'.join(','.join(str(x) for x in row) for row in M)

# ----------------------------
# Demo / CLI
# ----------------------------
def demo():
    playfair_kw = "SECURITYKEY"
    example_K = [[3,10,20],[20,17,15],[9,4,17]]
    print("Playfair keyword:", playfair_kw)
    print("Hill K matrix:")
    print(matrix_to_str(example_K))
    print("det(K) mod26:", det_3x3(example_K))

    sample_plain = "HELLOWORLDTHISISASECRETMESSAGE"
    print("\nPlaintext:", sample_plain)

    ciphertext = encrypt(sample_plain, playfair_kw, example_K)
    print("\nCiphertext:", ciphertext)

    recovered = decrypt(ciphertext, playfair_kw, example_K)
    print("\nRecovered plaintext (after decryption):", recovered)

    passphrase = "my strong passphrase"
    M_from_pass, used_ctr = build_hill_from_passphrase(passphrase)
    print("\nHill matrix derived from passphrase (ctr={}):".format(used_ctr))
    print(matrix_to_str(M_from_pass))
    print("det mod26:", det_3x3(M_from_pass))

def main(argv):
    parser = argparse.ArgumentParser(prog="playfair_hill_fixed.py", 
                                   description="Custom Cipher: Playfair + Hill Combination")
    sub = parser.add_subparsers(dest='cmd', help='Available commands')

    # Encrypt command
    p_enc = sub.add_parser('encrypt', help='Encrypt a message')
    p_enc.add_argument('--pf-key', required=True, help='Playfair keyword (min 10 alphabetic chars)')
    p_enc.add_argument('--hill', required=True, type=parse_matrix_arg, 
                      help='Hill matrix as "a,b,c;d,e,f;g,h,i"')
    p_enc.add_argument('plaintext', help='Message to encrypt')

    # Decrypt command  
    p_dec = sub.add_parser('decrypt', help='Decrypt a message')
    p_dec.add_argument('--pf-key', required=True, help='Playfair keyword')
    p_dec.add_argument('--hill', required=True, type=parse_matrix_arg,
                      help='Hill matrix as "a,b,c;d,e,f;g,h,i"')
    p_dec.add_argument('ciphertext', help='Ciphertext to decrypt')

    # Demo command
    p_demo = sub.add_parser('demo', help='Run demonstration')

    # Derive key command
    p_derive = sub.add_parser('derive-k', help='Derive Hill matrix from known plaintext')
    p_derive.add_argument('--pf-key', required=False, help="Playfair key if deriving from visible plaintext")
    p_derive.add_argument('--known-intermediate', required=False,
                          help="Known intermediate plaintext (post-Playfair). Must be multiple of 3 and >=9 letters.")
    p_derive.add_argument('--known-visible', required=False,
                          help="Known visible plaintext segment (pre-Playfair). Use with --pf-key.")
    p_derive.add_argument('--cipher', required=True, help="Corresponding Hill ciphertext segment (same length as known).")

    # Attack command (new)
    p_attack = sub.add_parser('attack', help='Run security analysis and attacks')
    p_attack.add_argument('--ciphertext', help='Ciphertext to analyze')
    p_attack.add_argument('--known-plain', help='Known plaintext for attack')
    p_attack.add_argument('--known-cipher', help='Known ciphertext for attack')
    p_attack.add_argument('--full-analysis', action='store_true', help='Run complete security analysis')

    args = parser.parse_args(argv)

    if args.cmd == 'encrypt':
        ct = encrypt(args.plaintext, args.pf_key, args.hill)
        print(ct)
        return

    if args.cmd == 'decrypt':
        pt = decrypt(args.ciphertext, args.pf_key, args.hill)
        print(pt)
        return

    if args.cmd == 'demo':
        demo()
        return

    if args.cmd == 'derive-k':
        if args.known_intermediate:
            K = derive_hill_from_known_pairs(args.known_intermediate.upper(), args.cipher.upper())
            print("Derived K from intermediate:")
            print(matrix_to_str(K))
            return
        if args.known_visible:
            if not args.pf_key:
                print("When using --known-visible you must also supply --pf-key", file=sys.stderr)
                sys.exit(1)
            K = derive_hill_from_visible_plaintext(args.known_visible.upper(), args.cipher.upper(), args.pf_key)
            print("Derived K from visible plaintext + Playfair key:")
            print(matrix_to_str(K))
            return
        print("Either --known-intermediate or --known-visible must be provided", file=sys.stderr)
        sys.exit(1)

    if args.cmd == 'attack':
        print("Security Analysis and Attacks")
        print("=" * 50)
        
        if args.full_analysis:
            # Import and run comprehensive analysis
            try:
                from attack import comprehensive_security_analysis
                comprehensive_security_analysis()
            except ImportError:
                print("Attack module not found. Please ensure 'attack.py' is in the same directory.")
        else:
            # Basic attack with provided data
            if args.ciphertext and args.known_plain and args.known_cipher:
                try:
                    from attack import CipherAttacker
                    attacker = CipherAttacker()
                    results = attacker.combined_attack(
                        args.ciphertext, 
                        args.known_plain, 
                        args.known_cipher
                    )
                    if results['success']:
                        print("Attack successful!")
                        print(f"Recovered plaintext: {results['recovered_plaintext']}")
                    else:
                        print("Attack failed - cipher provides reasonable security")
                except ImportError:
                    print("Attack module not found. Please ensure 'attack.py' is in the same directory.")
            else:
                print("For attacks, provide --ciphertext, --known-plain, and --known-cipher")
                print("Or use --full-analysis for comprehensive security assessment")

        return

    parser.print_help()

if __name__ == "__main__":
    main(sys.argv[1:])