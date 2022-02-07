#importing timer to measure operation 
import time
#importing AES
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

#Generate Random key 16bits
key = get_random_bytes(16)

#start timer on the function
begin = time.time()

#encryption algorithm
def encrypt(file):
    #c = E(k, p) 
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    #message encoded to ascii(bits)
    ciphertext, tag = cipher.encrypt_and_digest(file.encode('utf-8'))
    return nonce, ciphertext, tag

end = time.time()
encryptiontime=end-begin


#decryption algorithm
def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        #return to letters
        return plaintext.decode('ascii')
    except:
        return False

#flie to be encrypted        
with open ('MyMsg.txt', 'r') as file:
    orig_msg = file.read()

print (f'Encrypting', file.name)
nonce, ciphertext, tag = encrypt(orig_msg)

with open('myencryption.txt', 'wb') as fileencrypted:
    fileencrypted.write(ciphertext)

print(f'It takes', encryptiontime, 'to encrypt the file')

plaintext = decrypt(nonce, ciphertext, tag)



# print(f'Cipher text: {ciphertext}')
# if not plaintext:
#     print('Message is corrupted')
# else:lpong 
#     print(f'Plain text: {plaintext}')
if not plaintext:
    print('Message is corrupted')
else:
    print (f'Your message is is encrypted. See the file ', fileencrypted.name, f'for your encrypted message')
