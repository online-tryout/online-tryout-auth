from auth.utils import *

import datetime
import pytest
import jwt

def test_token_scheme():
    secret = {
        "id": "id",
        "other_info": "other_info"
    }

    exp =  datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)

    token = create_token(secret, "user", exp)

    assert type(token) == str

    info = read_token(token)

    assert type(info) == dict
    assert "id" in info
    assert "other_info" in info

def test_altered_token_scheme():
    secret = {
        "id": "id",
        "other_info": "other_info"
    }

    exp =  datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)

    token = create_token(secret, "user", exp)

    payload = jwt_decrypt(token)
    b64_encoded_data = payload.get("data")
    decoded_data_bytes = base64.urlsafe_b64decode(b64_encoded_data)
    decoded_data = decoded_data_bytes.decode().replace("\'", "\"")

    data = json.loads(decoded_data)

    data['d1'] = "modified data"

    encrypted_data = base64.urlsafe_b64encode(str({"d1": data['d1'], "d2": data['d2'], "d3": data['d3']}).encode()).decode()
    token_payload = {"data": encrypted_data, "username": "user"}
    tampered_token = jwt_encrypt(token_payload)

    result = read_token(tampered_token)

    assert result == False

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
