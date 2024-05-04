from pydantic import BaseModel, EmailStr
from typing import Optional

import uuid

class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: int

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: uuid.UUID
    model_config = {"from_attributes": True}

class UserRoleBase(BaseModel):
    id: int
    type: str

class UserRoleCreate(UserRoleBase):
    pass

class UserRole(UserRoleBase):
    model_config = {"from_attributes": True}