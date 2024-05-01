from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
with open("aes_key.bin", "wb") as f:
    f.write(key)
