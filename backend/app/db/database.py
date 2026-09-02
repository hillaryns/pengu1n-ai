import json
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DEFAULT_DATABASE_URL = "sqlite:///./pengu1n.db"

_engine = None
SessionLocal = None


class Base(DeclarativeBase):
    pass


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)


def configure_database(database_url: str | None = None) -> None:
    global _engine, SessionLocal

    url = database_url or get_database_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    _engine = create_engine(url, connect_args=connect_args)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)


def init_db() -> None:
    if _engine is None:
        configure_database()
    from app.db import models  # noqa: F401

    Base.metadata.create_all(bind=_engine)


def get_session():
    if SessionLocal is None:
        configure_database()
    return SessionLocal()


def dispose_database() -> None:
    global _engine, SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    SessionLocal = None


def reset_database() -> None:
    if _engine is None:
        configure_database()
    from app.db import models  # noqa: F401

    Base.metadata.drop_all(bind=_engine)
    Base.metadata.create_all(bind=_engine)
