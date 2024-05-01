#CREDIT: https://www.fastapitutorial.com/blog/unit-testing-in-fastapi/
from typing import Any
from typing import Generator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) 

from database import Base, get_db
from auth.router import router as auth_router

def start_application():
    app = FastAPI()
    app.include_router(auth_router, prefix="/api/auth")
    return app

SQLALCHEMY_DATABASE_URL = f"""
postgresql://{os.environ["USERNAME"]}:{os.environ["POSTGRES_PASSWORD"]}@localhost:5432/auth-test
"""

engine = create_engine(
    SQLALCHEMY_DATABASE_URL.strip()
)
SessionTesting = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="module")
def app() -> Generator[FastAPI, Any, None]:
    """
    Create a fresh database on each test case.
    """
    Base.metadata.create_all(engine)  
    _app = start_application()
    yield _app
    # Base.metadata.drop_all(engine)
     # Get table names in reverse order to drop them safely
    table_names = reversed(Base.metadata.sorted_tables)
    
    # Drop tables using raw SQL queries
    with engine.connect() as connection:
        for table_name in table_names:
            cmd = f"""DROP TABLE "{table_name}" CASCADE;"""
            connection.execute(text(cmd))


@pytest.fixture(scope="module")
def db_session_global(app: FastAPI) -> Generator[SessionTesting, Any, None]: # type: ignore
    connection = engine.connect()
    connection.begin()
    session = SessionTesting(bind=connection)
    yield session
    session.close()
    connection.close()


@pytest.fixture(scope="module")
def client(
    app: FastAPI, db_session_global: SessionTesting # type: ignore
) -> Generator[TestClient, Any, None]:
    """
    Create a new FastAPI TestClient that uses the `db_session_global` fixture to override
    the `get_db` dependency that is injected into routes.
    """

    def _get_test_db():
        try:
            yield db_session_global
        finally:
            pass

    app.dependency_overrides[get_db] = _get_test_db
    with TestClient(app) as client:
        yield client
        