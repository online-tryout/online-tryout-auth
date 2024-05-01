from sqlalchemy.orm import Session
from auth import models, schemas

import uuid
import re

def create_user(db: Session, user: schemas.UserCreate):
    try:
        new_user = models.User(
            username = user.username,
            is_admin = user.is_admin,
            password = user.password
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except Exception as e:
        raise ValueError(handle_exception(e))

def get_user(db: Session, user_id: uuid.UUID):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def update_user(db: Session, user_id: uuid.UUID, data: schemas.UserBase):
    user = get_user(db, user_id)
    if not user:
        raise LookupError("user not found")
    try:
        for key, value in data.items():
            setattr(user, key, value)
        db.commit()
        db.refresh(user)
        return user
    except Exception as e:
        raise ValueError(handle_exception(e))

def delete_user(db: Session, user_id: uuid.UUID):
    affected_rows = db.query(models.User).filter(models.User.id == user_id).delete()
    if affected_rows == 0:
        raise LookupError("user not found")
    db.commit()
    return True

def handle_exception(exception):
    pattern = r"Key \(([^)]+)\)"
    matches = re.findall(pattern, str(exception))
    if matches:
        return f"{matches[0]} already exists"
    else:
        #TODO: Log the error
        return "unknown error"