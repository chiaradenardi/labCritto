import string
import numpy as np
import matplotlib.pyplot as plt 

def substitute_encrypt(message, key):
    """Encrypt message using character substitution. Key is a random permutation of the 26 letters"""
    # map message to numerical array in range(0,26)
    plain = [x - ord('a') for x in map(ord,message)]
    # apply substitution according to key
    cipher = [key[x] for x in plain]
    # rewrite numerical array in uppercase letters
    cryptogram = [chr(x+ord('A')) for x in cipher]
    return ''.join(cryptogram)
    
def substitute_decrypt(cryptogram, key):
    """Decrypt cryptogram using character substitution. Key is a random permutation of the 26 letters"""
    # map cryptogram to numerical array in range(0,26)
    cipher = [x - ord('A') for x in map(ord,cryptogram)]
    # compute inverse permutation
    rev_key = np.argsort(key)
    # apply inverse substitution according to key
    plain = [rev_key[x] for x in cipher]
    # rewrite numerical array in lowercase letters
    message = [chr(x+ord('a')) for x in plain]
    return ''.join(message)


def Vigenere_encrypt(message, key):
    """Encrypt message using Vigenere algorithm. Key is a password."""
    # map message to numerical array in range(0,26)
    plain = [x - ord('a') for x in map(ord,message)]
    # map key (password) to numerical array in range(0,26)
    keynum = [x - ord('a') for x in map(ord,key)]
    # allocate empty array
    cipher = [0] * len(plain)
    i = 0
    klen = len(key)
    for k in keynum:
        # substistute one character every klen characters according to key[i]
        cipher[i::klen] = [(x + k) % 26 for x in plain[i::klen] ]
        i = i + 1
    # rewrite numerical array in uppercase letters
    cryptogram = [chr(x+ord('A')) for x in cipher]
    return ''.join(cryptogram)
    
def Vigenere_decrypt(cryptogram, key):
    """Encrypt message using Vigenere algorithm. Key is a password."""
    # map cryptogram to numerical array in range(0,26)
    cipher = [x - ord('A') for x in map(ord,cryptogram)]
    # map key (password) to numerical array in range(0,26)
    keynum = [x - ord('a') for x in map(ord,key)]
    # allocate empty array
    plain = [0] * len(cipher)
    i = 0
    klen = len(key)
    for k in keynum:
        # substistute one character every klen characters according to key[i]
        plain[i::klen] = [(x - k) % 26 for x in cipher[i::klen] ]
        i = i + 1
    # rewrite numerical array in lowercase letters
    message = [chr(x+ord('a')) for x in plain]
    return ''.join(message)
    



def monogram_ranking(cryptogram, topn=None):
    """Returns the topn most frequent monograms (letters) in cryptogram"""
    # map letters to numerical values in range(0,26)
    cipher = [x - ord('A') for x in map(ord,cryptogram)]
    # compute histogram of letter values
    freq = np.histogram(cipher, 26, (-0.5, 25.5))
    # get sorted letters in decreasing order of their frequency
    sorted_monograms = [(chr(x+ord('A')), freq[0][x]) for x in np.argsort(-freq[0])]
    return sorted_monograms[0:topn]


def digram_to_number(t, i):
    return 26*(ord(t[i]) - ord('A')) + ord(t[i+1]) - ord('A')
    
def number_to_digram(x):
    return ''.join([chr(x // 26 + ord('A')), chr(x % 26 + ord('A'))])


def digram_ranking(cryptogram, topn=None):
    """Returns the topn most frequent digrams (letter pairs) in cryptogram"""
    # map digrams to numerical values in range(0,26*26)
    digrams = [digram_to_number(cryptogram, i) for i in range(0,len(cryptogram)-1)]
    # compute histogram of digram values
    freq = np.histogram(digrams, 26*26, (-0.5, 26*26-0.5))
    # get sorted digrams in decreasing order of their frequency
    sorted_digrams = [(number_to_digram(x), freq[0][x]) for x in np.argsort(-freq[0])]
    return sorted_digrams[0:topn]
    
    
def trigram_to_number(t, i):
    return 26*26*(ord(t[i]) - ord('A')) + 26*(ord(t[i+1]) - ord('A')) + ord(t[i+2]) - ord('A')
        
def number_to_trigram(x):
    return ''.join([chr(x // (26*26) + ord('A')), chr((x % (26*26) // 26) + ord('A')), chr(x % 26 + ord('A'))])

def trigram_ranking(cryptogram, topn=None):
    """Returns the topn most frequent trigrams (letter triplets) in cryptogram"""
    # map trigrams to numerical values in range(0,26*26*26)
    trigrams = [trigram_to_number(cryptogram, i) for i in range(0,len(cryptogram)-2)]
    # compute histogram of trigram values
    freq = np.histogram(trigrams, 26*26*26, (-0.5, 26*26*26-0.5))
    # get sorted trigrams in decreasing order of their frequency
    sorted_trigrams = [(number_to_trigram(x), freq[0][x]) for x in np.argsort(-freq[0])]
    return sorted_trigrams[0:topn]
    

def crypto_freq(cryptogram):
    """Returns the relative frequencies of characters in  cryptogram"""
    # map letters to numerical values in range(0,26)
    cipher = [x - ord('A') for x in map(ord,cryptogram)]
    # compute histogram of letter values
    freq = np.histogram(cipher, 26, (-0.5, 25.5))
    # return relative frequency
    return freq[0] / len(cipher)
    
    
    
def periodic_corr(x, y):
    """Periodic correlation, implemented using the FFT. x and y must be real sequences with the same length."""
    return np.fft.ifft(np.fft.fft(x) * np.fft.fft(y).conj()).real
    

def main():
    # frequency of English letters in alphabetical order
    english_letter_freqs = [0.085516907,
    0.016047959,
    0.031644354,
    0.038711837,
    0.120965225,
    0.021815104,
    0.020863354,
    0.049557073,
    0.073251186,
    0.002197789,
    0.008086975,
    0.042064643,
    0.025263217,
    0.071721849,
    0.074672654,
    0.020661661,
    0.001040245,
    0.063327101,
    0.067282031,
    0.089381269,
    0.026815809,
    0.010593463,
    0.018253619,
    0.001913505,
    0.017213606,
    0.001137563]
    
    with open("cryptogram02.txt","r") as text_file:
        cryptogram = text_file.read()

    #stampa del file critto
    print(cryptogram)
    #lettera più presente
    print(monogram_ranking(cryptogram, 5))
    #top 2 lettere
    print(digram_ranking(cryptogram, 5))
    #topn most frequent trigrams
    print(trigram_ranking(cryptogram, 10))
    
        
    #ESERCIZIO 1
    #monoalphabetic substitution cipher
    #grafico frequenza delle lettere inglese
    """ letters = list(string.ascii_uppercase)
    
    plt.figure() # Create a new figure for petal length
    plt.bar(letters, english_letter_freqs,  color='skyblue', edgecolor='black')
    plt.title('Histogram of lettere alf')
    plt.xlabel('lettere')
    plt.ylabel('Frequency')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7) 
    
    freq_monogram=monogram_ranking(cryptogram, 26)
    
    # Dividi in due liste: lettere e frequenze
    letters = [x[0] for x in freq_monogram]
    frequencies = [x[1] for x in freq_monogram]

    plt.figure() # Create a new figure for petal length
    plt.bar(letters, frequencies,  color='skyblue', edgecolor='black')
    plt.title('Histogram of letters in the cyphertext')
    plt.xlabel('lettere')
    plt.ylabel('Frequency')
    plt.legend()
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.show()
     """
    #W probabilmente è la E--> fxw=the --> f=t; x=h; w=e
    #z=a, r=n, n=d
    subs = {'W': 'e', 'X': 'h', 'F': 't', 'Z': 'a', 'N': 'd', 'R': 'n'}
    guess01 = cryptogram
    for old, new in subs.items():
        guess01 = guess01.replace(old, new)
    #print(guess01)
    subs2= {'W': 'e', 'X': 'h', 'F': 't', 'Z': 'a', 'N': 'd', 'R': 'n','Y': 'b', 'J': 'i', 'A': 's', 'M': 'o', 'K':'w', 'H':'r', 'P':'p','I':'l', 'D':'y', 'B':'g', 'U':'c', 'T':'m', 'G':'u','V':'f', 'C':'q', 'S':'k', 'L':'v', 'E':'x', 'Q':'z'}
    guess02 = cryptogram
    for old, new in subs2.items():
        guess02 = guess02.replace(old, new)
    #print(guess02)
    #manca una lettera nel testo, ovvero la O che diventa la J
    
    
    #ESERCIZIO 2
    #vigenere cipher
    
    n = 100
    maxkeylen = len(cryptogram) // n
    scores = []

    for keylen in range(1, int(maxkeylen) + 1):
        S_total = 0

        # per ogni possibile offset nella chiave
        for start in range(keylen):
            subsequence = cryptogram[start::keylen][:n]  # ogni keylen, primi 100 caratteri
            if len(subsequence) < n:
                continue  # salta se troppo corto
            q = crypto_freq(subsequence)
            S_total += sum(q[i]**2 for i in range(len(q)))

        # media su tutte le sottosequenze
        S_avg = S_total / keylen
        scores.append(S_avg)

        print(f"keylen={keylen}, indice medio di coincidenza={S_avg:.4f}")
        
    print("keylenght:", np.argmax(scores)+1)  # +1 perché keylen parte da 1
    print("max score:", max(scores))

    # se vuoi, puoi anche visualizzare il grafico per capire dove “salta fuori” il picco
    """ plt.figure()
    plt.plot(range(1, int(maxkeylen) + 1), scores, marker='o')
    plt.title("Indice di coincidenza medio vs lunghezza chiave")
    plt.xlabel("Key length")
    plt.ylabel("Indice di coincidenza medio (S)")
    plt.grid(True)
    plt.show() """

    
        # ES2 PARTE 2 - Cracking key Vigenere corretto
    keylen = np.argmax(scores) + 1  # chiave stimata
    key = ''

    for j in range(keylen):
        subsequence = cryptogram[j::keylen]
        if len(subsequence) == 0:
            key += '?'  # non abbastanza dati
            continue
        freq = crypto_freq(subsequence)
        corr = periodic_corr(freq, english_letter_freqs)
        k = int(np.argmax(corr))
        key += chr(k + ord('a'))  # shift inverso per decifrare

    print("Chiave stimata:", key)

    # Decriptaggio
    plaintext = Vigenere_decrypt(cryptogram, key)
    print("Test decifratura (prime 500 lettere):\n", plaintext[:1000])

        
    
if __name__ == '__main__':
    main()






