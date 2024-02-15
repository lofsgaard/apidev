from dotenv import load_dotenv, find_dotenv
import os
from sqlmodel import create_engine
from sqlalchemy.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio.engine import AsyncEngine
from sqlalchemy.orm import sessionmaker

load_dotenv(find_dotenv())

DATABASE_URL = os.environ.get('DATABASE_URL')
engine = AsyncEngine(create_engine(DATABASE_URL, echo=True, future=True))
manual_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session():
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
