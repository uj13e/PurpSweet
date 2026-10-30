"""SQLAlchemy engine / session / Base."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .config import settings

# check_same_thread=False: the proxy runs in its own thread and also writes.
engine = create_engine(
    settings.db_url,
    connect_args={"check_same_thread": False},
    future=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


def init_db() -> None:
    from . import models  # noqa: F401  (register models)

    Base.metadata.create_all(bind=engine)
    _migrate()


def _migrate() -> None:
    """Tiny additive migrations for columns added after a DB already existed.
    SQLAlchemy's create_all never ALTERs existing tables, so add new columns
    here (SQLite supports ADD COLUMN). Safe to run on every startup."""
    from sqlalchemy import text
    wanted = {
        "findings": [("flow_id", "INTEGER DEFAULT 0")],
    }
    with engine.begin() as conn:
        for table, cols in wanted.items():
            try:
                existing = {r[1] for r in conn.execute(text(f"PRAGMA table_info({table})"))}
            except Exception:
                continue
            if not existing:
                continue  # table not created yet
            for name, decl in cols:
                if name not in existing:
                    try:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {decl}"))
                    except Exception:
                        pass


def get_session():
    """FastAPI dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
