import jwt

from hashlib import sha256

def get_key():
    with open("aes_key.bin", "rb") as key_file:
        key = key_file.read()
        return key

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

