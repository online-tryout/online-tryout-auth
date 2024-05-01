from sqlalchemy import Boolean, Column, String
from sqlalchemy.dialects.postgresql import UUID

import uuid

from database import Base

class User(Base):
    __tablename__ = "user"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String, unique=True)
    password = Column(String)
    is_admin = Column(Boolean, default=False)