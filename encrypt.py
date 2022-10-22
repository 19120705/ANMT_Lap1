
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
# from .encrypt import encrypt
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
# from bs4 import Tag
import hashlib
import binascii


def generate_RSA(bits=2048):
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    '''
    #from Crypto.PublicKey import RSA 
    new_key = RSA.generate(bits, e=65537) 
    public_key = new_key.publickey().exportKey("PEM") 
    private_key = new_key.exportKey("PEM") 
    return public_key,private_key

#ENCRYPT K_PRI WITH AES
def AES_encrypt(key,message):
    cipher=AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    #ciphertext,tag =cipher.encrypt_and_digest(message.encode('ascii'))
    ciphertext,tag =cipher.encrypt_and_digest(message)
    return nonce, ciphertext, tag

def AES_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce )
    plaintext = cipher.decrypt(ciphertext)
    try: 
        cipher.verify(tag)
        return plaintext
    except:
        return False


#Encrypt file
def test_encypt(session_key,enc_session_key,filename):
    with open(filename, 'rb') as f:
        data= f.read()
    file_out = open(filename+"_encrypt", "wb")
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()

def test_decrypt(private_key,filename):
    file_in = open(filename+"_encrypt", "rb")
    enc_session_key, nonce, tag, ciphertext = [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    with open(filename+"_decrypt", 'wb') as out:
        out.write(data)

def sign_file(filename,private_key):
    with open(filename, 'rb') as f:
        msg_b = f.read()
    #msg = b'A message for signing'
    hash = SHA256.new(msg_b)
    signer = PKCS115_SigScheme(private_key)
    signature = signer.sign(hash)
    file_out = open(filename+".sig", "wb")
    [ file_out.write(x) for x in (signature,msg_b) ]
    file_out.close()
    

def verify_file(sign_filename,filename,public_key):
    #msg = b'hello vn 123 @'
    with open(filename, 'rb') as f:
        msg= f.read()
    
    #print(msg)
    
    file_in = open(sign_filename, "rb")
    signature,msg_2 = [file_in.read(x) for x in (256, -1) ]
    #print(msg_2)
    #print(signature)
    hash = SHA256.new(msg)
    signer = PKCS115_SigScheme(public_key)
    try:
        signer.verify(hash, signature)
        return True
    except:
        return False