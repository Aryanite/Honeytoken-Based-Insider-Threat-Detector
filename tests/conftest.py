import os
import tempfile
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from backend.db.base import Base
from backend.db.session import get_db
from backend.main import app

# Isolated temporary database for tests — never touches the development DB
TEST_DIR = tempfile.mkdtemp()
TEST_DATABASE_PATH = os.path.join(TEST_DIR, "test_suite.db")
TEST_DATABASE_URL = f"sqlite:///{TEST_DATABASE_PATH}"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 30},
)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
)


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    """
    Provide a clean database for each test function.
    Tables are created before the test and dropped after.
    """
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest_asyncio.fixture(scope="function")
async def client(db_session: Session) -> AsyncGenerator[AsyncClient, None]:
    """
    Provide an async HTTP test client with per-request database sessions.
    """
    def override_get_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
    app.dependency_overrides.clear()
