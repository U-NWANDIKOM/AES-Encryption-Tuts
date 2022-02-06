
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#Generate Random key 16bits
key = get_random_bytes(16)

#encryption algorithm
def encrypt(msg):
    #c = E(k, p) 
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    #message encoded to ascii(bits)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        #return to letters
        return plaintext.decode('ascii')
    except:
        return False

nonce, ciphertext, tag = encrypt(input('Enter a message: '))
plaintext = decrypt(nonce, ciphertext, tag)

print(f'Cipher text: {ciphertext}')
if not plaintext:
    print('Message is corrupted')
else:
    print(f'Plain text: {plaintext}')
