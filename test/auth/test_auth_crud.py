import pytest
import uuid

from auth.models import User
from auth.utils import hash_password
from auth.crud import *

@pytest.fixture()
def db_session(db_session_global):
    session = db_session_global
    data = {
        "username": "test_user",
        "password": hash_password("password"),
    }
    user = User(**data)
    data = {
        "username": "test_user2",
        "password": hash_password("password"),
    }
    user2 = User(**data)
    session.add(user)
    session.add(user2)
    session.commit()

    yield session

    session.rollback()
    session.query(User).delete()
    session.commit()
    session.close()

class TestAuthCRUD:
    def test_successful_register(self, db_session):
        data = {
            "username": "new_user",
            "password": hash_password("password"),
        }
        result = create_user(db_session, User(**data))

        assert result.username == "new_user"
        assert result.is_admin == False
    
    def test_fail_register_username_already_exists(self, db_session):
        data = {
            "username": "test_user",
            "password": hash_password("password"),
        }

        with pytest.raises(ValueError) as exc_info:
            create_user(db_session, User(**data))
        assert str(exc_info.value) == "username already exists"

    def test_successful_get_user(self, db_session):
        user = db_session.query(User).filter(User.username == "test_user").first()
        result = get_user(db_session, user.id)

        assert result == user

    def test_fail_get_user(self, db_session):
        result = get_user(db_session, uuid.uuid4())

        assert result == None

    def test_successful_get_user_by_username(self, db_session):
        result = get_user_by_username(db_session, "test_user")

        assert result.username == "test_user"

    def test_fail_get_user_by_username(self, db_session):
        result = get_user_by_username(db_session, "non_existent_user")

        assert result == None

    def test_successful_update_user(self, db_session):
        user = db_session.query(User).filter(User.username == "test_user").first()
        data = {
            "username": "test_user_updated",
        }
        result = update_user(db_session, user.id, data)

        assert result.username == "test_user_updated"

        updated_user = db_session.query(User).filter(User.username == "test_user_updated").first()
        assert updated_user.username == "test_user_updated"


    def test_fail_update_user_not_found(self, db_session):
        data = {
            "username": "test_user",
        }

        with pytest.raises(LookupError) as exc_info:
            update_user(db_session, uuid.uuid4(), data)
        assert str(exc_info.value) == "user not found"

    def test_fail_update_user_username_already_registered(self, db_session):
        user = db_session.query(User).filter(User.username == "test_user").first()
        data = {
            "username": "test_user2",
        }

        with pytest.raises(ValueError) as exc_info:
            update_user(db_session, user.id, data)
        assert str(exc_info.value) == "username already exists"

    def test_successful_delete_user(self, db_session):
        user = db_session.query(User).filter(User.username == "test_user").first()
        result = delete_user(db_session, user.id)

        assert result == True

        deleted_user = db_session.query(User).filter(User.username == "test_user").first()
        assert deleted_user == None

    def test_fail_delete_user(self, db_session):
        with pytest.raises(LookupError) as exc_info:
            delete_user(db_session, uuid.uuid4())
        assert str(exc_info.value) == "user not found"
