from pydantic import BaseModel
from typing import Optional
import uuid

class UserBase(BaseModel):
    username: str
    is_admin: Optional[bool] = False

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: uuid.UUID
    model_config = {"from_attributes": True}