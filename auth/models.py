from sqlalchemy import Column, String, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

import uuid

from database import Base

class User(Base):
    __tablename__ = "user"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    password = Column(String)

    role_relationship = relationship("UserRole", back_populates="users")
    role = Column(Integer, ForeignKey("userRole.id"))

class UserRole(Base):
    __tablename__ = "userRole"

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String, unique=True)

    users = relationship("User", back_populates="role_relationship")