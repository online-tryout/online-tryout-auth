from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

import os
from dotenv import load_dotenv

load_dotenv()

# SQLALCHEMY_DATABASE_URL = f"""
# postgresql://{os.environ["USERNAME"]}:{os.environ["POSTGRES_PASSWORD"]}@localhost:5432/auth
# """
SQLALCHEMY_DATABASE_URL = os.environ["SUPABASE_DB_URL"]

engine = create_engine(
    SQLALCHEMY_DATABASE_URL.strip()
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()