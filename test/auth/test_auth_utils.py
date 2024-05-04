from auth.utils import *

import datetime
import pytest
import jwt

def test_token_scheme():
    secret = {
        "id": "id",
        "other_info": "other_info"
    }

    token = jwt_encrypt(secret)

    assert type(token) == str

    info = jwt_decrypt(token)

    assert type(info) == dict
    assert "id" in info
    assert "other_info" in info

def test_altered_token_scheme():
    secret = {
        "id": "id",
        "other_info": "other_info"
    }

    token = jwt_encrypt(secret)

    payload = jwt_decrypt(token)
    payload["other_info"] = "altered_info"

    header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    token = jwt.encode(payload, "", algorithm='HS256', headers=header)

    with pytest.raises(jwt.InvalidSignatureError):
        jwt_decrypt(token)

def test_hash_password():
    password = "password"
    hashed_password = hash_password(password)

    assert type(hashed_password) == str

    assert hashed_password != password
    assert hashed_password == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"

def test_jwt_expiration():
    data = {
        "data": "some data",
        "exp": datetime.datetime.now(tz=datetime.timezone.utc)
    }
    token = jwt_encrypt(data)

    with pytest.raises(jwt.ExpiredSignatureError):
        jwt_decrypt(token)
