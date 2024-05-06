from auth.models import User, UserRole
from auth.utils import *
from auth.crud import *

import pytest
import base64

@pytest.fixture()
def db_session(db_session_global):
    session = db_session_global
    
    data = {
        "id": 1,
        "type": "User"
    }
    role = UserRole(**data)
    data = {
        "id": 2,
        "type": "Admin"
    }
    role2 = UserRole(**data)
    session.add(role)
    session.add(role2)
    session.commit()

    data = {
        "name": "test_user",
        "email": "test@gmail.com",
        "password": hash_password("password"),
        "role_id": 1
    }
    user = User(**data)
    data = {
        "name": "test_user2",
        "email": "test2@gmail.com",
        "password": hash_password("password"),
        "role_id": 1
    }
    user2 = User(**data)
    data = {
        "name": "admin",
        "email": "admin@gmail.com",
        "password": hash_password("password"),
        "role_id": 2
    }
    admin = User(**data)
    session.add(user)
    session.add(user2)
    session.add(admin)
    session.commit()

    yield session

    session.rollback()
    session.query(User).delete()
    session.query(UserRole).delete()
    session.commit()
    session.close()

class TestAuthRouter:
    def test_successful_register_normal_user(self, client, db_session):
        data = {
            "name": "new_user",
            "email": "new_user@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii"),
            "role_id": 1
        }
        response = client.post("api/auth/register", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "user registered successfully"

        user = get_user_by_email(db_session, "new_user@gmail.com")
        assert user.name == "new_user"
        assert user.role_id == 1
        assert user.password == hash_password("password")

    def test_successful_register_admin(self, client, db_session):
        data = {
            "email": "admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        client.post("api/auth/login", json=data)

        data = {
            "name": "new_admin",
            "email": "new_admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii"),
            "role_id": 2
        }
        response = client.post("api/auth/register", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "user registered successfully"

        user = get_user_by_email(db_session, "new_admin@gmail.com")
        assert user.name == "new_admin"
        assert user.role_id == 2
        assert user.password == hash_password("password")

    def test_fail_register_admin_unauthorized_guest(self, client, db_session):
        client.post("api/auth/logout")
        data = {
            "name": "new_admin",
            "email": "new_admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii"),
            "role_id": 2
        }
        response = client.post("api/auth/register", json=data)

        assert response.status_code == 401
        assert response.json()["detail"] == "token not found"

    def test_fail_register_admin_unauthorized_normal_user(self, client, db_session):
        client.post("api/auth/logout")
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)
        
        data = {
            "name": "new_admin",
            "email": "new_admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii"),
            "role_id": 2
        }
        response = client.post("api/auth/register", json=data)

        assert response.status_code == 403
        assert response.json()["detail"] == "unauthorized"
    
    def test_fail_register_name_already_exists(self, client, db_session):
        data = {
            "name": "test_user2",
            "email": "test2@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii"),
            "role_id": 1
        }

        response = client.post("api/auth/register", json=data)

        assert response.status_code == 409
        assert response.json()["detail"] == "email already exists"

    def test_successful_create_role(self, client, db_session):
        data = {
            "email": "admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        client.post("api/auth/login", json=data)

        data = {
            "id": 9,
            "type": "Lecturer"
        }
        response = client.post("api/auth/role", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "role created successfully"

    def test_fail_create_role_unauthorized(self, client, db_session):
        client.post("api/auth/logout")
        data = {
            "id": 9,
            "type": "Lecturer"
        }
        response = client.post("api/auth/role", json=data)

        assert response.status_code == 401
        assert response.json()["detail"] == "token not found"

        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        client.post("api/auth/login", json=data)

        data = {
            "id": 9,
            "type": "Lecturer"
        }
        response = client.post("api/auth/role", json=data)

        assert response.status_code == 403
        assert response.json()["detail"] == "unauthorized"

    def test_fail_create_role_already_exists(self, client, db_session):
        data = {
            "email": "admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        client.post("api/auth/login", json=data)

        data = {
            "id": 3,
            "type": "Admin"
        }
        response = client.post("api/auth/role", json=data)

        assert response.status_code == 409
        assert response.json()["detail"] == "type already exists"

    def test_successful_login(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        token = response.cookies["token"]
        info = jwt_decrypt(token)
        assert type(info) == dict
        
        assert "id" in info.keys()
        assert "name" in info.keys()
        assert "role_id" in info.keys()
        assert info["name"] == "test_user"

    def test_fail_login_wrong_password(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"wrong_password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 401
        assert response.json()["detail"] == "invalid credentials"
        
    def test_fail_login_user_not_found(self, client, db_session):
        data = {
            "email": "whoami@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 401
        assert response.json()["detail"] == "invalid credentials"

    def test_successful_update_info(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        data = {
            "name": "new_username"
        }
        response = client.post("api/auth/update_info", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "user updated successfully"

        user = get_user_by_email(db_session, "test@gmail.com")
        assert user

    def test_fail_update_info_not_logged_in(self, client, db_session):
        client.cookies.clear()
        data = {
            "name": "new_username"
        }
        response = client.post("api/auth/update_info", json=data)

        assert response.status_code == 401
        assert response.json()["detail"] == "token not found"

    def test_fail_update_info_trying_to_update_role(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        client.post("api/auth/login", json=data)

        data = {
            "role_id": 2
        }
        response = client.post("api/auth/update_info", json=data)

        assert response.status_code == 403
        assert response.json()["detail"] == "role cannot be changed"

    def test_fail_update_info_user_not_found(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        token_data = jwt_decrypt(response.cookies["token"])
        user_id = token_data["id"]

        delete_user(db_session, user_id)

        data = {
            "name": "new_username"
        }
        response = client.post("api/auth/update_info", json=data)

        assert response.status_code == 404
        assert response.json()["detail"] == "user not found"

    def test_fail_update_info_email_already_exists(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        data = {
            "email": "test2@gmail.com"
        }
        response = client.post("api/auth/update_info", json=data)

        assert response.status_code == 409
        assert response.json()["detail"] == "email already exists"

    def test_fail_update_info_invalid_data(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        data = {
            "id": "1"
        }
        response = client.post("api/auth/update_info", json=data)

        assert response.status_code == 403
        assert response.json()["detail"]== "id cannot be updated"

    def test_successful_update_role(self, client, db_session):
        data = {
            "email": "admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        data = {
            "type": "Banned User"
        }
        response = client.post("api/auth/role/1", json=data)
        
        assert response.status_code == 200
        assert response.json()["message"] == "role updated successfully"

    def test_fail_update_role(self, client, db_session):
        client.post("api/auth/logout")
        data = {
            "type": "Banned User"
        }
        response = client.post("api/auth/role/1", json=data)

        assert response.status_code == 401
        assert response.json()["detail"] == "token not found"

        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        data = {
            "type": "Banned User"
        }
        response = client.post("api/auth/role/1", json=data)

        assert response.status_code == 403
        assert response.json()["detail"] == "unauthorized"

        data = {
            "email": "admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        data = {
            "type": "Banned User"
        }
        response = client.post("api/auth/role/99", json=data)

        assert response.status_code == 404
        
        data = {
            "id": 1,
            "type": "Banned User"
        }
        response = client.post("api/auth/role/2", json=data)

        assert response.status_code == 409
        assert response.json()["detail"] == "id already exists"

    def test_logout(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        response = client.post("api/auth/logout")

        assert response.status_code == 200
        assert "token" not in response.cookies
        assert "token" not in client.cookies

    def test_successful_delete_user(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        response = client.post("api/auth/delete_user")

        assert response.status_code == 200
        assert response.json()["message"] == "user deleted successfully"
        assert "token" not in response.cookies
        assert "token" not in client.cookies

        user = get_user_by_email(db_session, "test@gmail.com")
        assert user == None

    def test_fail_delete_user_not_found(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        user = get_user_by_email(db_session, "test@gmail.com")

        delete_user(db_session, user.id)

        response = client.post("api/auth/delete_user")

        assert response.status_code == 404
        assert response.json()["detail"] == "user not found"

    def test_fail_delete_user_no_token(self, client, db_session):
        client.cookies.clear()
        response = client.post("api/auth/delete_user")

        assert response.status_code == 401
        assert response.json()["detail"] == "token not found"

    def test_successful_delete_user_by_admin(self, client, db_session):
        data = {
            "email": "admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        user = get_user_by_email(db_session, "test@gmail.com")

        response = client.post(f"api/auth/delete_user/{user.id}")

        assert response.status_code == 200

        user = get_user_by_email(db_session, "test@gmail.com")
        assert user == None

    def test_fail_delete_user_by_admin_user_not_found(self, client, db_session):
        data = {
            "email": "admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        user = get_user_by_email(db_session, "test@gmail.com")

        delete_user(db_session, user.id)

        response = client.post(f"api/auth/delete_user/{user.id}")

        assert response.status_code == 404
        assert response.json()["detail"] == "user not found"

    def test_fail_delete_user_by_admin_unauthorized(self, client, db_session):
        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        response = client.post("api/auth/login", json=data)

        assert response.status_code == 200
        assert response.json()["message"] == "login successful"
        assert "token" in response.cookies

        user = get_user_by_email(db_session, "test@gmail.com")

        response = client.post(f"api/auth/delete_user/{user.id}")

        assert response.status_code == 403
        assert response.json()["detail"] == "unauthorized"

    def test_fail_delete_user_by_admin_no_token(self, client, db_session):
        client.cookies.clear()
        user = get_user_by_email(db_session, "test@gmail.com")

        response = client.post(f"api/auth/delete_user/{user.id}")

        assert response.status_code == 401
        assert response.json()["detail"] == "token not found"

    def test_success_delete_role(self, client, db_session):
        data = {
            "email": "admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        client.post("api/auth/login", json=data)

        data = {
            "id": 9,
            "type": "Lecturer"
        }
        response = client.post("api/auth/role", json=data)

        response = client.post("api/auth/role/9/delete")

        assert response.status_code == 200
        assert response.json()["message"] == "role deleted successfully"

    def test_fail_delete_role(self, client, db_session):
        client.post("api/auth/logout")

        response = client.post("api/auth/role/9/delete")
        assert response.status_code == 401

        data = {
            "email": "test@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        client.post("api/auth/login", json=data)

        response = client.post("api/auth/role/9/delete")
        assert response.status_code == 403

        data = {
            "email": "admin@gmail.com",
            "password": base64.b64encode(b"password").decode("ascii")
        }
        client.post("api/auth/login", json=data)

        response = client.post("api/auth/role/99/delete")
        assert response.status_code == 404

        response = client.post("api/auth/role/2/delete")
        assert response.status_code == 403
        assert response.json()["detail"] == "there are users with this role. please make sure this role is not still in use"



