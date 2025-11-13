import sys
import os
import time
from random import randrange, getrandbits
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# 2048-bit group of order q based on Z_p^* with p=2*q+1, p,q primes
# p, q, g as recommended in RFC 7919 for Diffie-Hellman key exchange

pDH = 0xFFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF

# generator of the subgroup of Z_p^* of order q
gDH = 2

qDH = 0x7FFFFFFFFFFFFFFFD6FC2A2C515DA54D57EE2B10139E9E78EC5CE2C1E7169B4AD4F09B208A3219FDE649CEE7124D9F7CBE97F1B1B1863AEC7B40D901576230BD69EF8F6AEAFEB2B09219FA8FAF83376842B1B2AA9EF68D79DAAB89AF3FABE49ACC278638707345BBF15344ED79F7F4390EF8AC509B56F39A98566527A41D3CBD5E0558C159927DB0E88454A5D96471FDDCB56D5BB06BFA340EA7A151EF1CA6FA572B76F3B1B95D8C8583D3E4770536B84F017E70E6FBF176601A0266941A17B0C8B97F4E74C2C1FFC7278919777940C1E1FF1D8DA637D6B99DDAFE5E17611002E2C778C1BE8B41D96379A51360D977FD4435A11C30942E4BFFFFFFFFFFFFFFFF

def encryptAESCTR(key, plaintext):
    """Encrypts plaintext using AES-CTR mode with given key
       key:       bytes-like object, should be 16, 24, or 32 bytes long
       plaintext: bytes-like object
       return iv, ciphertext as bytes-like objects
    """
    # 128-bit iv, securely generated
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext)
    
    
def decryptAESCTR(key, iv, ciphertext):
    """Decrypts ciphertext encrypted using AES-CTR mode with given key and iv
       key:        bytes-like object, should be 16, 24, or 32 bytes long
       iv:         bytes-like object, should be 16 bytes long
       ciphertext: bytes-like object
       return plaintext as bytes-like object
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
    

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

    
def generate_prime_candidate(length):
    """ Generate an odd integer via secure random generator
        Args:
            length -- int -- the length of the number to generate, in bits
        return an odd integer in range(sqrt(2)*2^(length-1), 2^length)
    """
    mask = (1 << length) - 1
    offs = 1.4142135623731 * (1 << (length-1))
    p = 0
    while p < offs:
        # generate big integer from random bytes
        p = int.from_bytes(os.urandom((length+7)//8), byteorder='little')
        # apply a mask to limit to length bits
        p &= mask
    # apply a mask to set LSB to 1
    p |=  1
    return p


def is_prime(n, k=128):
    """ Test if a number is prime using Miller-Rabin test
        Args:
            n -- int -- the number to test
            k -- int -- the number of tests to do
        return True if n is prime
        (the probability of false positive is bounded by 1/4^k)
    """
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s such that n-1 = r*2^s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        # if a^r mod n = +-1 then n may be prime so continue with the next a
        if x != 1 and x != n - 1:
            j = 1
            # if a^(2^j * r) mod n = -1 then n may be prime so continue
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                # if x^2 mod n = 1 but x mod n != +-1 then n is not prime, so end the test
                if x == 1:
                    return False
                j += 1
            # if a^r mod n != 1 and a^(2^j * r) mod n != -1 for every j in (0,s-1) then n is not prime, so end the test
            if x != n - 1:
                return False
    return True  
    

    
def encodeText(s, bitlen):
    """Encode string s in a list of positive integers each representable with bitlen-8 bits (bitlen // 8 - 1 bytes)"""
    sbytes = bytearray(s.encode('utf-8'))
    # do not use most significant byte
    bytelen = (bitlen // 8) -1
    m = []
    while len(sbytes) > bytelen:
        m.append(int.from_bytes(sbytes[:bytelen], byteorder='little'))
        sbytes[:bytelen] = []
    m.append(int.from_bytes(sbytes, byteorder='little'))
    return m
    
    
def decodeText(m, bitlen):
    """Decode a list of positive integers each representable with bitlen-8 bits (bitlen // 8 - 1 bytes) into a string s.
        Ensures decodeText(encodeText(s, bitlen), bitlen) == s"""
    # do not use most significant byte
    bytelen = (bitlen // 8) -1
    mbytes = bytearray()
    for x in m:
        mbytes += x.to_bytes(bytelen, byteorder='little')
    return mbytes.rstrip(b'\x00').decode('utf-8')

#e generato randomicamente, deve essere minore o uguale di 2^16 +1
def rnd_e():
    e = randrange(3, 2**16 + 1, 2)
    return e

# returns (g,x,y) where g = GCD(a,b) and x,y verify x*a + y*b = g 
def egcd(a, b): 
    if a == 0: 
        return (b, 0, 1) 
    else: 
        g, x, y = egcd(b % a, a) 
        return (g, y - (b // a) * x, x)
    
def main():
    RSA_N=84679728665601623534964724907925515929006540043189517481604602443064696359792213876789134073333039587280256381629121330309212710075084136072434602842735932397920567074126295940793758270599694063151970957022891161811181118800418280560581409959172714364916927401331291518944188508877716559336163266657183044021    
    RSA_e=65537
    s_group5= "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim."
    m_group5= 0x4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f726520657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2e
    keylen = 1024

    print("INIZIO ESERCIZIO")
    
    #encrypt a mex with a public key (RSA_N, RSA_e) c=m^e mod N
    #prima abbiamo trasformato il mex in una sequenza di bytes e poi in un intero
    mex_bytes=bytearray(s_group5.encode('utf-8'))
    m= int.from_bytes(mex_bytes, byteorder='little')
    c=pow(m,RSA_e, RSA_N)
    print("Messaggio cifrato con RSA:", c)
    
    found=False
    
    while(not found):
        pPK=generate_prime_candidate(keylen//2)
        qPK=generate_prime_candidate(keylen//2)
        if is_prime(pPK,100) and is_prime(qPK,100) and pPK!=qPK:
            print("p primo:",pPK)
            print("q primo:",qPK)
            found=True
    N=pPK*qPK
    print("N generato:", N)

    N=140873413212511132111073298003193134834962185826892050021408536774112903010822289926702145760573986568764201843003637270923696767289547891742335101086945578292823398864050624080579636392523360821246851221045082847939251434147045876293375468541709895236316948375457938498487143716183202041812056603320810007083
    p=13321806997141103789515694844630398204620593269175689047785623647737223883920399665249355004412001659552365918057081867565581873212407799465416736119151061
    q=10574647511613323313363713745092085628133724093990154496064003331211163092496653990681671920477672529289803243755238045177691192732012256300882303464059903
    phiN=(p-1)*(q-1)
    print("phi(N) calcolato.", phiN)
    
    while(True):
        e=rnd_e()
        g,x,y=egcd(e,phiN)
        if g==1:
            d= x % phiN
            break
        
    print("Esponente pubblico e generato:", e)
    print("Esponente privato d generato:", d)
    
    e=5009
    d=28714664581747627447675351818977877952983907312688517283261752055573821915362259535868015735984436072411309658955223328730903254023283768710106635697698425042661736235161831732161237502517540059160512538303208488176648075057103397461320352925253641580940865729013444765087734648117931729249984508019790888169
    c=22424902779751505285951085490013996696589674815858922696735281532664544132347080434867516880409203997944359748445324275935386253926651012009550485750638582403445072437514414309461607597003225816081058645177221992457984945882096762867809580647779046311439349324961819343650289746939671091951218353909929433392
    m_decr = pow(c, d, N)
    mex_decr_string = decodeText([m_decr], keylen)
    print("Messaggio decrittato con RSA:", mex_decr_string)
    
    # p = generate_prime_candidate(keylen//2)
    # q = generate_prime_candidate(keylen//2)
    # # this is not a valid RSA modulo, p and q should be tested for primality!
    # N = p*q
    # try:
    #     assert N.bit_length() == keylen
    # except AssertionError:
    #     print('N generation error:')
    #     print('size of N is', N.bit_length(), 'bits instead of', keylen)
    #     sys.exit(1)
        
    # print('p:', p)
    # print('q:', q)
    # print('N:', N)
    # print('p is prime:', is_prime(p, 100))
    # print('q is prime:', is_prime(q, 100))
    # print('17 is prime:', is_prime(17, 100))
    # print('15 is prime:', is_prime(15, 100))
    
    
    # s = "Today’s programs need to be able to handle a wide variety of characters. Applications are often internationalized to display messages and output in a variety of user-selectable languages; the same program might need to output an error message in English, French, Japanese, Hebrew, or Russian. Web content can be written in any of these languages and can also include a variety of emoji symbols. Python’s string type uses the Unicode Standard for representing characters, which lets Python programs work with all these different possible characters."
    
    
    # print('s:', s)
    # m = encodeText(s, keylen)
    # print('m:', m)
    
    # #integers in m can be safely encrypted using a RSA key on keylen bits
    
    # s2 = decodeText(m, keylen)
    # print('decoded m:', s2)
    # try:
    #     assert s == s2
    # except AssertionError:
    #     print('message decoding error:')
    #     print('message is:')
    #     print(s)
    #     print('decoded message is:')
    #     print(s2)
    #     sys.exit(1)
    

    
    # key = os.urandom(16)
    # plaintext = s.encode('utf-8')
    
    # # first call may take longer to execute due to crypto library initializations
    # start_time = time.time()
    # (iv, ciphertext) = encryptAESCTR(key, plaintext)
    # elapsed_time = time.time() - start_time
    # print('AES encryption time (first call):', elapsed_time)
    
    # start_time = time.time()
    # plaintext = decryptAESCTR(key, iv, ciphertext)
    # elapsed_time = time.time() - start_time
    # print('AES decryption time:', elapsed_time)
    
    # plaintext = s.encode('utf-8')
    # # this call should be much faster
    # start_time = time.time()
    # (iv, ciphertext) = encryptAESCTR(key, plaintext)
    # elapsed_time = time.time() - start_time
    # print('AES encryption time (second call):', elapsed_time)
    
    # start_time = time.time()
    # plaintext = decryptAESCTR(key, iv, ciphertext)
    # elapsed_time = time.time() - start_time
    # print('AES decryption time:', elapsed_time)
    
    # try:
    #     assert s == plaintext.decode('utf-8')
    # except AssertionError:
    #     print('AES error:')
    #     print('message is:')
    #     print(s)
    #     print('decrypted message is:')
    #     print(plaintext.decode('utf-8'))
    #     sys.exit(1)
    
    
    
    
if __name__ == '__main__':
    main()
