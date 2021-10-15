import uuid
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.sql import text
from sqlalchemy import Table, Column, Integer, String, DateTime, MetaData
from sqlalchemy.dialects.postgresql import UUID, TEXT
from datetime import datetime

from .models import *
from .config import cfg


_engine = create_async_engine(cfg.DB_CONNECTION_STRING)
_metadata = MetaData()


accounts = Table('accounts', _metadata,
    Column('id', Integer, primary_key=True),
    Column('role', String, default='user', nullable=False),
    Column('login', String, unique=True, nullable=False),
    Column('password', TEXT, nullable=False),
    Column('name', String, nullable=False),
    Column('register_time', DateTime, default=datetime.utcnow, nullable=False)
)


async def check_database():
    try:
        async with _engine.begin() as conn:
            answer = await conn.execute(text("SELECT version();"))
            print(f'Successfully connecting to database.\n{answer.first()}')
    except Exception as e:
        print(f'Failed to connect to database:\n{str(e)}')


async def recreate_tables():
    async with _engine.begin() as conn:
        print('Dropping existing tables - ', end='', flush=True)
        try:
            await conn.run_sync(_metadata.reflect)
            await conn.run_sync(_metadata.drop_all)
            print('OK')
        except Exception as e:
            print(f'Failed to drop tables.\n{str(e)}')

        print('Creating tables - ', end='', flush=True)
        await conn.run_sync(_metadata.create_all)
        print('OK')
