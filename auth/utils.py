from Crypto.Cipher import AES
import jwt
import base64
import json
import datetime

from hashlib import sha256

def get_key():
    with open("aes_key.bin", "rb") as key_file:
        key = key_file.read()
        return key
    
def create_token(payload, username, exp):
    nonce, cipher, tag = encrypt_aes(str(payload))
    nonce = base64.urlsafe_b64encode(nonce).decode()
    cipher = base64.urlsafe_b64encode(cipher).decode()
    tag = base64.urlsafe_b64encode(tag).decode()

    encrypted_data = base64.urlsafe_b64encode(str({"d1": nonce, "d2": cipher, "d3": tag}).encode()).decode()
    token_payload = {
        "data": encrypted_data, 
        "username": username,
        "exp": exp
    }
    return jwt_encrypt(token_payload)

def read_token(token):
    payload = jwt_decrypt(token)
    b64_encoded_data = payload.get("data")
    decoded_data_bytes = base64.urlsafe_b64decode(b64_encoded_data)
    decoded_data = decoded_data_bytes.decode().replace("\'", "\"")

    data = json.loads(decoded_data)

    d1 = data.get("d1")
    d2 = data.get("d2")
    d3 = data.get("d3")

    nonce = base64.urlsafe_b64decode(d1.encode())
    cipher = base64.urlsafe_b64decode(d2.encode())
    tag = base64.urlsafe_b64decode(d3.encode())
    result = decrypt_aes(nonce, cipher, tag)
    if not result:
        return False
    
    token_data = json.loads(result.replace("\'", "\""))
    token_data["username"] = payload.get("username")
    return token_data

def encrypt_aes(inp):
    key = get_key()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(inp.encode("ascii"))
    return nonce, ciphertext, tag

def decrypt_aes(nonce, ciphertext, tag):
    key = get_key()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode("ascii")
    except:
        return False

def jwt_encrypt(data):
    key = get_key()
    header = {
        "alg": "HS256",
        "typ": "JWT"
    }

    payload = data
    return jwt.encode(payload, key, algorithm='HS256', headers=header)

def jwt_decrypt(data):
    key = get_key()
    return jwt.decode(data, key, algorithms=['HS256'])

def hash_password(password):
    return sha256(password.encode("utf-8")).hexdigest()

