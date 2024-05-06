from sqlalchemy import Column, DateTime, func, String, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

import uuid

from database import Base

class User(Base):
    __tablename__ = "user"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    avatar = Column(String)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    role = relationship("UserRole", back_populates="users")
    role_id = Column(Integer, ForeignKey("userRole.id"))

class UserRole(Base):
    __tablename__ = "userRole"

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String, unique=True)

    users = relationship("User", back_populates="role")