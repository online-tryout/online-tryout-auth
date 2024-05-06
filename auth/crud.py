from sqlalchemy.orm import Session
from auth import models, schemas

import uuid
import re

def create_user(db: Session, user: schemas.UserCreate):
    try:
        new_user = models.User(
            name = user.name,
            email = user.email,
            password = user.password,
            role_id = user.role_id
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return new_user
    except Exception as e:
        raise ValueError(handle_exception(e))
    
def create_user_role(db: Session, user_role: schemas.UserRoleCreate):
    try:
        new_role = models.UserRole(
            id = user_role.id,
            type = user_role.type
        )
        db.add(new_role)
        db.commit()
        db.refresh(new_role)
        return new_role
    except Exception as e:
        raise ValueError(handle_exception(e))

def get_user(db: Session, user_id: uuid.UUID):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_all_roles(db: Session):
    return db.query(models.UserRole).all()

def get_user_role_by_id(db: Session, role_id: int):
    return db.query(models.UserRole).filter(models.UserRole.id == role_id).first()

def get_user_role_by_type(db: Session, type: str):
    return db.query(models.UserRole).filter(models.UserRole.type == type).first()

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
    
def update_role(db: Session, user_role_id: int, data: schemas.UserRoleBase):
    user_role = get_user_role_by_id(db, user_role_id)
    if not user_role:
        raise LookupError("role not found")
    try:
        for key, value in data.items():
            setattr(user_role, key, value)
        db.commit()
        db.refresh(user_role)
        return user_role
    except Exception as e:
        raise ValueError(handle_exception(e))

def delete_user(db: Session, user_id: uuid.UUID):
    affected_rows = db.query(models.User).filter(models.User.id == user_id).delete()
    if affected_rows == 0:
        raise LookupError("user not found")
    db.commit()
    return True

def delete_user_role(db: Session, user_role_id: int):
    try:
        affected_rows = db.query(models.UserRole).filter(models.UserRole.id == user_role_id).delete()
    except Exception as e:
        print(e)
        raise ValueError("there are users with this role. please make sure this role is not still in use")

    if affected_rows == 0:
        raise LookupError("role not found")
    db.commit()
    return True
    
def handle_exception(exception):
    pattern = r"Key \(([^)]+)\)"
    matches = re.findall(pattern, str(exception))
    if matches:
        return f"{matches[0]} already exists"
    else:
        #TODO: Log the error
        print(f"Unknown exception occured: {str(exception)}")
        return "unknown error"