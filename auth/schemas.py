from pydantic import BaseModel, EmailStr
from typing import Optional

import uuid

class UserBase(BaseModel):
    name: str
    email: EmailStr
    role_id: int
    avatar: Optional[str] = ""

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