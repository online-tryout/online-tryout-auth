import pytest
import uuid

from auth.models import User, UserRole
from auth.utils import hash_password
from auth.crud import *

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
    session.add(user)
    session.add(user2)
    session.commit()

    yield session

    session.rollback()
    session.query(User).delete()
    session.query(UserRole).delete()
    session.commit()
    session.close()

class TestAuthCRUD:
    def test_successful_register(self, db_session):
        data = {
            "name": "new_user",
            "email": "new_user@gmail.com",
            "password": hash_password("password"),
            "role_id": 1
        }
        result = create_user(db_session, User(**data))

        assert result.name == "new_user"
        assert result.role_id == 1

    def test_fail_register_email_already_exists(self, db_session):
        data = {
            "name": "test_user3",
            "email": "test@gmail.com",
            "password": hash_password("password"),
            "role_id": 1
        }

        with pytest.raises(ValueError) as exc_info:
            create_user(db_session, User(**data))
        assert str(exc_info.value) == "email already exists"

    def test_successful_create_role(self, db_session):
        data = {
            "id": 3,
            "type": "Test Role"
        }
        result = create_user_role(db_session, UserRole(**data))

        assert result.type == "Test Role"
        assert result.id == 3

    def test_fail_create_role(self, db_session):
        data = {
            "id": 3,
            "type": "Admin"
        }

        with pytest.raises(ValueError) as exc_info:
            create_user_role(db_session, UserRole(**data))
        assert str(exc_info.value) == "type already exists"

    def test_successful_get_user(self, db_session):
        user = db_session.query(User).filter(User.name == "test_user").first()
        result = get_user(db_session, user.id)

        assert result == user

    def test_fail_get_user(self, db_session):
        result = get_user(db_session, uuid.uuid4())

        assert result == None

    def test_successful_get_user_by_email(self, db_session):
        result = get_user_by_email(db_session, "test@gmail.com")

        assert result.email == "test@gmail.com"

    def test_fail_get_user_by_email(self, db_session):
        result = get_user_by_email(db_session, "whoami@gmail.com")

        assert result == None

    def test_successful_get_role(self, db_session):
        result = get_user_role_by_id(db_session, 1)

        assert result.type == "User"

    def test_successful_get_all_roles(self, db_session):
        result = get_all_roles(db_session)

        assert len(result) == 2

    def test_successful_get_role_by_type(self, db_session):
        result = get_user_role_by_type(db_session, "Admin")

        assert result.id == 2

    def test_successful_update_user(self, db_session):
        user = db_session.query(User).filter(User.name == "test_user").first()
        data = {
            "name": "test_user_updated",
        }
        result = update_user(db_session, user.id, data)

        assert result.name == "test_user_updated"

        updated_user = db_session.query(User).filter(User.name == "test_user_updated").first()
        assert updated_user.name == "test_user_updated"


    def test_fail_update_user_not_found(self, db_session):
        data = {
            "name": "test_user",
        }

        with pytest.raises(LookupError) as exc_info:
            update_user(db_session, uuid.uuid4(), data)
        assert str(exc_info.value) == "user not found"

    def test_fail_update_user_email_already_registered(self, db_session):
        user = db_session.query(User).filter(User.email == "test@gmail.com").first()
        data = {
            "email": "test2@gmail.com",
        }

        with pytest.raises(ValueError) as exc_info:
            update_user(db_session, user.id, data)
        assert str(exc_info.value) == "email already exists"

    def test_successful_update_role(self, db_session):
        role = db_session.query(UserRole).filter(UserRole.id == 1).first()
        data = {
            "type": "Normal User"
        }
        result = update_role(db_session, role.id, data)

        assert result.type == "Normal User"

        updated_role = db_session.query(UserRole).filter(UserRole.id == 1).first()
        
        assert updated_role.type == "Normal User"

    def test_fail_update_role(self, db_session):
        role = db_session.query(UserRole).filter(UserRole.id == 1).first()
        data = {
            "type": "Admin"
        }
        with pytest.raises(ValueError) as exc_info:
            update_role(db_session, role.id, data)
        assert str(exc_info.value) == "type already exists"

    def test_fail_update_role_not_found(self, db_session):
        data = {
            "type": "Admin"
        }
        with pytest.raises(LookupError) as exc_info:
            update_role(db_session, 999999, data)
        assert str(exc_info.value) == "role not found"

    def test_successful_delete_user(self, db_session):
        user = db_session.query(User).filter(User.name == "test_user").first()
        result = delete_user(db_session, user.id)

        assert result == True

        deleted_user = db_session.query(User).filter(User.name == "test_user").first()
        assert deleted_user == None

    def test_fail_delete_user(self, db_session):
        with pytest.raises(LookupError) as exc_info:
            delete_user(db_session, uuid.uuid4())
        assert str(exc_info.value) == "user not found"

    def test_successful_delete_role(self, db_session):
        role = db_session.query(UserRole).filter(UserRole.id == 2).first()
        result = delete_user_role(db_session, role.id)

        assert result == True

        deleted_role = db_session.query(UserRole).filter(UserRole.id == 2).first()
        assert deleted_role == None

    def test_fail_delete_role(self, db_session):
        role = db_session.query(UserRole).filter(UserRole.id == 1).first()
        with pytest.raises(ValueError) as exc_info:
            delete_user_role(db_session, role.id)
        assert str(exc_info.value) == "there are users with this role. please make sure this role is not still in use"

    def test_fail_delete_role_not_found(self, db_session):
        with pytest.raises(LookupError) as exc_info:
            delete_user_role(db_session, 999999999)
        assert str(exc_info.value) == "role not found"