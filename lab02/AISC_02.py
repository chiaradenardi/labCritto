# Simplified AES using multiple rounds.
# Simplified AES maps 16-bit words in 16-bit words using a 16-bit key
# It's internal state is a 2x2 matrix of 4-bit values (nibbles)
# The input is copied onto the initial state and modified using
# AES-like transforms: AddKey, NibbleSubstitute, ShiftRow, MixColumns
# Derived from Python 3 implementation in:
#
# Author: Joao H de A Franco (jhafranco@acm.org)
#
# Description: Simplified AES implementation in Python 3
#
# Date: 2012-02-11
#
# License: Attribution-NonCommercial-ShareAlike 3.0 Unported
#          (CC BY-NC-SA 3.0)
#===========================================================
import sys
import random
import statistics
import base64
 
# S-Box
sBox  = [0x9, 0x4, 0xa, 0xb, 0xd, 0x1, 0x8, 0x5,
         0x6, 0x2, 0x0, 0x3, 0xc, 0xe, 0xf, 0x7]
 
# Inverse S-Box
sBoxI = [0xa, 0x5, 0x9, 0xb, 0x1, 0x7, 0x8, 0xf,
         0x6, 0x0, 0x2, 0x3, 0xc, 0x4, 0xd, 0xe]
 
# Round keys: K0 = w0 + w1; K1 = w2 + w3; K2 = w4 + w5; K3 = w6 + w7; K4 = w8 + w9;
w = [None] * 10
 
def mult(p1, p2):
    """Multiply two polynomials in GF(2^4)/x^4 + x + 1"""
    p = 0
    while p2:
        # at ith iteration, if ith coeff of p2 is set, add p1*x^i mod x^4+x+1 to result
        if p2 & 0b1:
            p ^= p1
        # compute p1 = p1*x mod x^4+x+1
        p1 <<= 1
        # if degree of p1 is > 3, subtract x^4+x+1
        if p1 & 0b10000:
            p1 ^= 0b11
        p2 >>= 1
    return p & 0b1111
 
def intToVec(n):
    """Convert a 2-byte integer into a 4-nibble vector"""
    return [n >> 12, (n >> 4) & 0xf, (n >> 8) & 0xf,  n & 0xf]
 
def vecToInt(m):
    """Convert a 4-nibble vector into 2-byte integer"""
    return (m[0] << 12) + (m[2] << 8) + (m[1] << 4) + m[3]
 
def addKey(s1, s2):
    """Add two keys in GF(2^4)"""
    return [i ^ j for i, j in zip(s1, s2)]
     
def sub4NibList(sbox, s):
    """Nibble substitution function"""
    return [sbox[e] for e in s]
     
def shiftRow(s):
    """ShiftRow function"""
    return [s[0], s[1], s[3], s[2]]
    
def mixCol(s):
    """Defined as [1 4; 4 1] * [s[0] s[1]; s[2] s[3]] in GF(2^4)/x^4 + x + 1"""
    return [s[0] ^ mult(4, s[2]), s[1] ^ mult(4, s[3]), s[2] ^ mult(4, s[0]), s[3] ^ mult(4, s[1])]

def iMixCol(s):
    """Defined as [9 2; 2 9] * [s[0] s[1]; s[2] s[3]] in GF(2^4)/x^4 + x + 1"""
    return [mult(9, s[0]) ^ mult(2, s[2]), mult(9, s[1]) ^ mult(2, s[3]), mult(9, s[2]) ^ mult(2, s[0]), mult(9, s[3]) ^ mult(2, s[1])]
 
def keyExp(key):
    """Generate the round keys (up to 4 rounds)"""
    def sub2Nib(b):
        """Swap each nibble and substitute it using sBox"""
        return sBox[b >> 4] + (sBox[b & 0x0f] << 4)
 
    Rcon1, Rcon2, Rcon3, Rcon4 = 0b10000000, 0b00110000, 0b01100000, 0b11000000
    w[0] = (key & 0xff00) >> 8
    w[1] = key & 0x00ff
    w[2] = w[0] ^ Rcon1 ^ sub2Nib(w[1])
    w[3] = w[2] ^ w[1]
    w[4] = w[2] ^ Rcon2 ^ sub2Nib(w[3])
    w[5] = w[4] ^ w[3]
    w[6] = w[4] ^ Rcon3 ^ sub2Nib(w[5])
    w[7] = w[6] ^ w[5]
    w[8] = w[6] ^ Rcon4 ^ sub2Nib(w[7])
    w[9] = w[8] ^ w[7]
    

def computeRound(subkey0, subkey1, state):
    # generic round: NS-SR-MC-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = mixCol(state)
    state = addKey(intToVec((subkey0 << 8) + subkey1), state)
    return state
    
def computeInvRound(subkey0, subkey1, state):
    # generic inverse round: AK-MC-SR-NS
    state = addKey(intToVec((subkey0 << 8) + subkey1), state)
    state = iMixCol(state)
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    return state
    
def lazyComputeRound(subkey0, subkey1, state):
    # generic round: NS-SR-MC-AK
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((subkey0 << 8) + subkey1), state)
    return state
 
def encrypt(ptext):
    """Encrypt plaintext block (2 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = computeRound(w[2], w[3], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec((w[4] << 8) + w[5]), state)
    
    return vecToInt(state)

def encrypt3round(ptext):
    """Encrypt plaintext block (3 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = computeRound(w[2], w[3], state)
    # second round
    state = computeRound(w[4], w[5], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec((w[6] << 8) + w[7]), state)
    
    return vecToInt(state)
     
def encrypt4round(ptext):
    """Encrypt plaintext block (4 rounds)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = computeRound(w[2], w[3], state)
    # second round
    state = computeRound(w[4], w[5], state)
    # third round
    state = computeRound(w[6], w[7], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec((w[8] << 8) + w[9]), state)
    
    return vecToInt(state)

def lazyEncrypt(ptext):
    """Encrypt plaintext block lazy way (no shift a mixCol)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = lazyComputeRound(w[2], w[3], state)
    # second round
    state = lazyComputeRound(w[4], w[5], state)
    # third round
    state = lazyComputeRound(w[6], w[7], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[8] << 8) + w[9]), state)
    
    return vecToInt(state)

def veryLazyEncrypt(ptext):
    """Encrypt plaintext block very lazy way (no key schedule, no shift, no mixCol)"""
        
    # first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ptext))
    # first round
    state = lazyComputeRound(w[0], w[1], state)
    # second round
    state = lazyComputeRound(w[0], w[1], state)
    # third round
    state = lazyComputeRound(w[0], w[1], state)
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)
     
def decrypt(ctext):
    """Decrypt ciphertext block (2 rounds)"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[4] << 8) + w[5]), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    # invert first round
    state = computeInvRound(w[2], w[3], state)
    # invert first AddKey
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)
    
def encrypt_foo(ptext):
    """Encrypt plaintext block"""
        
    # last round: NS-SR-AK
    state = sub4NibList(sBox, intToVec(ptext))
    state = shiftRow(state)
    state = addKey(intToVec((w[0] << 8) + w[1]), state)
    
    return vecToInt(state)

def decrypt_foo(ctext):
    """Decrypt ciphertext block"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec((w[0] << 8) + w[1]), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    
    return vecToInt(state)


def encrypt_1r_2k(ptext, k0, k1):
    """Encrypt plaintext block (1 round) using two independent subkeys - no key schedule"""
        
    # first AddKey
    state = addKey(intToVec(k0), intToVec(ptext))
    # last round: NS-SR-AK
    state = sub4NibList(sBox, state)
    state = shiftRow(state)
    state = addKey(intToVec(k1), state)
    
    return vecToInt(state)

     
def decrypt_1r_2k(ctext, k0, k1):
    """Decrypt ciphertext block (1 round) using two independent subkeys - no key schedule"""
    
    # invert last round: AK-SR-NS
    state = addKey(intToVec(k1), intToVec(ctext))
    state = shiftRow(state)
    state = sub4NibList(sBoxI, state)
    # invert first AddKey
    state = addKey(intToVec(k0), state)
    
    return vecToInt(state)



def hamming (x, y):
    return bin(x ^ y).count('1')
    
 
if __name__ == '__main__':
    print("########################################")
    print("### ESECUZIONE DEL BONUS TASK ###")
    print("########################################\n")

    # --- Dati forniti dal problema ---
    known_pairs = [
        (0b0111001001101110, 0b0011011101111111), # m0, c0
        (0b1101001101001001, 0b1111110001001110), # m1, c1
        (0b1011010011100101, 0b1000100100001000)  # m2, c2
    ]

    # Convertiamo i plain/cipher noti in vettori di nibble per l'analisi
    known_m_vecs = [intToVec(m) for m, c in known_pairs]
    known_c_vecs = [intToVec(c) for m, c in known_pairs]
    
    # Applichiamo P_inv (che è shiftRow) a tutti i ciphertext noti
    # P_inv(c) = [c0, c1, c3, c2]
    known_c_inv_vecs = [shiftRow(c_vec) for c_vec in known_c_vecs]

    # Variabili per salvare i nibble delle chiavi trovate
    found_w = [None] * 4 # Questo diventerà k0 = [w0, w1, w2, w3]
    found_z = [None] * 4 # Questo diventerà P_inv(k1) = [z0, z1, z2, z3]

    # --- FASE 1: ATTACCO MEET-IN-THE-MIDDLE ---
    print("--- Inizio attacco Meet-in-the-Middle per trovare k0 e k1 ---")

    # Iteriamo su ogni posizione del nibble (i = 0, 1, 2, 3)
    for i in range(4):
        #print(f"--- Attaccando la posizione {i} del nibble ---")
        candidates = []

        # Brute-force su 16 (per w) * 16 (per z) = 256 possibilità
        for w_guess in range(16): # 4 bit per w_i
            for z_guess in range(16): # 4 bit per z_i
                
                is_valid_for_all_pairs = True
                
                # Verifichiamo la coppia (w, z) su TUTTE le coppie m/c note
                for j in range(len(known_pairs)):
                    m_vec = known_m_vecs[j]
                    c_inv_vec = known_c_inv_vecs[j]

                    # Equazione d'oro: [P_inv(c)]_i ^ z_i = S([m]_i ^ w_i)
                    
                    # Lato Sinistro (LHS): [P_inv(c)]_i ^ z_i
                    lhs = c_inv_vec[i] ^ z_guess
                    
                    # Lato Destro (RHS): S([m]_i ^ w_i)
                    rhs = sBox[m_vec[i] ^ w_guess]

                    # Se non corrispondono, questa coppia (w,z) è errata
                    if lhs != rhs:
                        is_valid_for_all_pairs = False
                        break # Passa alla prossima coppia (w,z)
                
                # Se la coppia (w,z) ha superato i controlli di *tutte* le coppie m/c...
                if is_valid_for_all_pairs:
                    # ...è una candidata valida
                    #print(f"  Trovato candidato per i={i}: w_{i}=0x{w_guess:x}, z_{i}=0x{z_guess:x}")
                    candidates.append((w_guess, z_guess))
        
        # Ci aspettiamo di trovare UN solo candidato
        if len(candidates) == 1:
            found_w[i] = candidates[0][0]
            found_z[i] = candidates[0][1]
            print(f"  [Nibble {i}] Chiavi parziali trovate: w_{i}=0x{found_w[i]:x}, z_{i}=0x{found_z[i]:x}")
        else:
            print(f"  [Nibble {i}] ERRORE: Trovati {len(candidates)} candidati. L'attacco potrebbe fallire.")


    # --- FASE 2: Ricostruzione delle Chiavi ---
    
    # k0 è la concatenazione diretta dei nibble w_i
    # k0 = [w0, w1, w2, w3]
    k0 = vecToInt(found_w)

    # z è P_inv(k1). Dobbiamo calcolare k1 = P(z)
    # P(z) è shiftRow(z)
    # z = [z0, z1, z2, z3]
    # k1 = [z0, z1, z3, z2]  <- shiftRow(z)
    k1_vec = shiftRow(found_z)
    k1 = vecToInt(k1_vec)

    print("\n--- CHIAVI FINALI RICOSTRUITE ---")
    print(f"k0 = {k0:016b} (0x{k0:04x})")
    print(f"k1 = {k1:016b} (0x{k1:04x})")

    # --- FASE 3: Verifica delle Chiavi (Opzionale ma consigliata) ---
    print("\n--- Verifica delle chiavi sulle coppie note ---")
    verification_ok = True
    for j in range(len(known_pairs)):
        m, c = known_pairs[j]
        c_test = encrypt_1r_2k(m, k0, k1)
        if c_test != c:
            verification_ok = False
        print(f"  Test coppia {j}: {c_test == c}")
    
    if not verification_ok:
        print("  *** ERRORE NELLA VERIFICA! Le chiavi trovate sono errate. ***")
        sys.exit(1)

    # --- FASE 4: Decrittografia del file 'ciphertext_2k.txt' ---
    print("\n--- Decrittografia di 'ciphertext_2k.txt' ---")
    
    try:
        # Apri il file in modalità 'read bytes' (rb)
        with open("lab02/ciphertext_2k.txt", "rb") as f:
            encryption_b64 = f.read()

        encryption = base64.b64decode(encryption_b64)
        rec_message = ""
        
        # Itera sui byte, decifra i blocchi e accumula i caratteri
        for b0, b1 in zip(*[iter(encryption)] * 2):
            ciphertext_block = (b0 << 8) + b1
            plaintext_block = decrypt_1r_2k(ciphertext_block, k0, k1)
            
            # Ricostruisci la stringa
            rec_message += chr((plaintext_block & 0xff00) >> 8)
            rec_message += chr(plaintext_block & 0x00ff)

        print("\n--- MESSAGGIO DECIFRATO ---")
        # Usiamo .rstrip() per rimuovere eventuali caratteri di padding
        print(rec_message.rstrip())
        print("---------------------------")

    except FileNotFoundError:
        print("\nERRORE: File 'ciphertext_2k.txt' non trovato.")
    except Exception as e:
        print(f"\nSi è verificato un errore durante la decrittografia del file: {e}")

    # --- FASE 5: Complessità dell'Attacco ---
    print("\n--- Complessità dell'Attacco ---")
    print("La complessità dell'attacco è data dalla formula (n/b) * (2^(2*b))")
    print("Dove:")
    print("  n = 16 bit (dimensione totale del blocco)")
    print("  b = 4 bit (dimensione dell'S-Box, o nibble)")
    print("\nCalcolo:")
    print("  Complessità = (16 / 4) * (2^(2 * 4))")
    print("  Complessità = 4 * (2^8)")
    print("  Complessità = 4 * 256")
    print("  Complessità = 1024")
    print("\nL'attacco richiede circa 1024 operazioni per nibble (più il filtraggio con le coppie aggiuntive), un numero estremamente basso.")
    
    # Test vectors from "Simplified AES" (Steven Gordon)
    # (http://hw.siit.net/files/001283.pdf)
    plaintext = 0b1101011100101000
    key = 0b0100101011110101
    ciphertext = 0b0010010011101100
    
    #FASE 1
    #ricreaiamo la fun encrypt foo ma ci fermiamo prima della add key bc vogliamo convertire il vettore
    known_plain = 0b0111001001101110 
    known_cipher = 0b0100000000001000  
    stato_int = intToVec(known_plain)
    stato_int=sub4NibList(sBox, stato_int)
    stato_int=shiftRow(stato_int)
    
    #fermarci prima della add key per fare il reverse e ottenere la chiave
    stato_int=vecToInt(stato_int)
    print("stato intermedio prima della add key:", " {0:016b}".format(stato_int))
    
    #ora tramite xor otteniamo la chiave (pText xor chiave --> inverso (x chiave)= ptext xor ctext)
    key_intermedia = stato_int ^ known_cipher
    print("chiave ottenuta:", " {0:016b}".format(key_intermedia))
    keyExp(key_intermedia)
    
    #leggiamo il file ciphertext.txt e decifriamo il messaggio (FASE 2)
    decrypted = decrypt_foo(known_cipher)
    try:
            with open("lab02/ciphertext.txt", "r") as text_file: 
                encryption = base64.b64decode(text_file.read())
                
            rec_message = ""
            
            # Itera sui byte, decifra i blocchi e accumula i caratteri
            for b0, b1 in zip(*[iter(encryption)] * 2):
                ciphertext_block = (b0 << 8) + b1
                plaintext_block = decrypt_foo(ciphertext_block)
                
                # Ricostruisci la stringa
                rec_message += chr((plaintext_block & 0xff00) >> 8)
                rec_message += chr(plaintext_block & 0x00ff)

            print("\n--- MESSAGGIO DECIFRATO ---")
            print(rec_message)
            print("---------------------------")

    except FileNotFoundError:
        print("\nERRORE: File 'ciphertext.txt' non trovato.")
    except Exception as e:
        print(f"\nSi è verificato un errore: {e}")  
    
    keyExp(key)
    
    try:
        assert encrypt(plaintext) == ciphertext
    except AssertionError:
        print("Encryption error")
        print(encrypt(plaintext), ciphertext)
        sys.exit(1)
    print("Test ok!")
    
    plaintext = random.getrandbits(16)
    error = 1 << random.randrange(16)
    plaintext2 = plaintext ^ error
    assert hamming(plaintext, plaintext2) == 1
    
    print("{0:016b} : plaintext".format(plaintext))
    print("{0:016b} : bit flip".format(error))
    print("{0:016b} : changed plaintext".format(plaintext2))
    ciphertext = encrypt(plaintext)
    ciphertext2 = encrypt(plaintext2)
    print("{0:016b} : ciphertext".format(ciphertext))
    print("{0:016b} : changed ciphertext".format(ciphertext2))

    # example of encryption of arbitrary text
    message = "This is a sample text "
    key = 0b1111111111111111
    keyExp(key)

    # initialize encryption buffer
    encryption = bytearray()

    # read pairs of characters from message
    for c0, c1 in zip(*[iter(message)] * 2):
        # convert (c0, c1) in 16-bit plaintext
        plaintext = (ord(c0) << 8) + ord(c1)
        ciphertext = encrypt_foo(plaintext)
        # extract bytes from 16-bit ciphertext and append them to encryption buffer
        encryption.append((ciphertext & 0xff00) >> 8)
        encryption.append(ciphertext & 0x00ff)

    # write encryption buffer in base64 encoding
    base64encryption = base64.b64encode(encryption).decode("utf-8")
    # decode base64 encoding
    encryption2 = base64.b64decode(base64encryption)
    # initialize decryption buffer
    rec_message = ""

    # read pairs of bytes from encryption buffer
    for b0, b1 in zip(*[iter(encryption2)] * 2):
        # convert (b0, b1) in 16-bit ciphertext
        ciphertext = (b0 << 8) + b1
        plaintext = decrypt_foo(ciphertext)
        # extract characters from 16-bit plaintext and append them to decryption buffer
        rec_message += chr((plaintext & 0xff00) >> 8)
        rec_message += chr(plaintext & 0x00ff)

    print('plaintext message:', message)
    print('encrypted message (base64):', base64encryption)
    print('decrypted message:', rec_message)
    
    print("NUOVO ESERCIZIOOOOOOOOOOOOOO")
    #scelta chiave, generato testo casuale ed effettuata encryption
    key=0b0000000011111111
    keyExp(key)
    print("key", " {0:016b}".format(key))
    avgDistHamm = []
    for i in range(1000):
        #flipping of a bit rand pos in the key, espandi chiave,encripta lo stesso testo con la nuova chiave
        plaintext = random.getrandbits(16) 
        ciphertext1 = veryLazyEncrypt(plaintext)
        error = 1 << random.randrange(16) 
        plaintext2 = plaintext ^ error
        # print("error {0:016b}".format(error))
        # print("changed plaintext {0:016b}".format(plaintext2))
        ciphertext2 = veryLazyEncrypt(plaintext2)
        # print("ciphertext1 {0:016b}".format(ciphertext1))
        
        #se stampa il print significa che i due testi differiscono di un solo carattere; se non è così il codice si ferma
        dist_hamm = hamming(ciphertext1, ciphertext2)
        # print("Hamming between plaintexts:", dist_hamm)
        avgDistHamm.append(dist_hamm)
        
    media = statistics.mean(avgDistHamm)
    print("La media della distanza di Hamming è:", media)
    
    
    plaintext = 0b1101011100101000 
    avgDistHamm = []
    for i in range(1000):
        #flipping of a bit rand pos in the key, espandi chiave,encripta lo stesso testo con la nuova chiave
        key1 = random.getrandbits(16)
        keyExp(key)
        ciphertext1 = veryLazyEncrypt(plaintext)
        error = 1 << random.randrange(16) 
        key2 = key1 ^ error
        keyExp(key2)
        ciphertext2 = veryLazyEncrypt(plaintext2)
        
        #se stampa il print significa che i due testi differiscono di un solo carattere; se non è così il codice si ferma
        dist_hamm = hamming(ciphertext1, ciphertext2)
        # print("Hamming between plaintexts:", dist_hamm)
        avgDistHamm.append(dist_hamm)
        
    media = statistics.mean(avgDistHamm)
    print("La media della distanza di Hamming è:", media)
    
    #modifica aes con 3 e 4 round e rifai esperimenti
       
    sys.exit()




