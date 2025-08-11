from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, declarative_base
from .config import Config

engine = create_engine(Config.SQLALCHEMY_DATABASE_URI, future=True, echo=False, pool_pre_ping=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base = declarative_base()

def init_db():
    Base.metadata.create_all(bind=engine)
