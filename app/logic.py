import uuid
import httpx
from passlib.hash import bcrypt
from fastapi import Request
from datetime import datetime, timedelta

from .database import accounts
from .database import _engine
from .config import cfg
from .errors import HTTPabort


def hash_password(password):
    return bcrypt.hash(password)


def verify_password(password, hashed_password):
    return bcrypt.verify(password, hashed_password)


async def register_account(login, password, name):
    async with _engine.begin() as conn:
        query = select(accounts).where(accounts.c.login == login)
        result = await conn.execute(query)
        account = result.first()

        if account:
            HTTPabort(409, 'Account with this login already exists')

        query = accounts.insert().values(role='user', login=login, name=name,
                                     password=hash_password(password),
                                     register_time=datetime.utcnow())
        await conn.execute(query)


async def me(current_user):
    async with _engine.begin() as conn:
        query = select(accounts).where(accounts.c.id == current_user.account_id)
        result = await conn.execute(query)
        account = result.first()

        return current_user.jsonify_info(account['login'], account['name'], account['register_time'])


async def get_account_info(login):
    async with _engine.begin() as conn:
        query = select(accounts).where(accounts.c.login == login)
        result = await conn.execute(query)
        account = result.first()

        if account:
            HTTPabort(409, 'No account with this login')

        return {
            'login': account['login'],
            'role': account['role'],
            'name': account['name'],
            'register_time': account['register_time']
        }


async def get_all_accounts(offset, limit, role):
    async with _engine.begin() as conn:
        query = select(accounts).order_by(desc(accounts.c.register_time))
        if role in ['user', 'admin']:
            query = query.where(accounts.c.role == role)
        if offset and limit:
            if offset < 0 or limit < 1:
                HTTPabort(422, 'Offset or limit has wrong values')
            else:
                query = query.limit(limit).offset(offset)

        result = await conn.execute(query)

        accounts = []
        for account in results:
            accounts.append({
                'login': account['login'],
                'name': account['name'],
                'role': account['role'],
                'register_time': account['register_time']
            })
        return accounts


async def change_password(current_user, old_password, new_password):
    async with _engine.begin() as conn:
        query = select(accounts).where(accounts.c.id == current_user.account_id)
        result = await conn.execute(query)
        account = result.first()

        if not verify_password(old_password, account.password)
            HTTPabort(422, 'Incorrect password')
        if old_password == new_password:
            HTTPabort(409, 'Old and new passwords are equal')

        async with httpx.AsyncClient() as ac:
            json = {
                'account_id': current_user.account_id,
                'session_id': current_user.session_id
            }
            answer = await ac.post(cfg.BA_DEL_SESSIONS_LINK, json=json)

            if answer.status_code != 200:
                HTTPabort(answer.status_code, answer.json()['content'])

        query = accounts.update().where(accounts.c.id == current_user.account_id).values(password=hash_password(new_password))
        await conn.execute(query)


async def verify_account(current_user, account):
    async with _engine.begin() as conn:
        query = select(accounts).where(accounts.c.id == current_user.account_id) if account.account_id else select(accounts).where(accounts.c.id == current_user.login)
        result = await conn.execute(query)
        acc = result.first()

        if not acc:
            HTTPabort(404, 'Account not found')
        if not verify_password(account.password, acc.password):
            HTTPabort(422, 'Incorrect password')

        return {
            'account_id': acc.id,
            'role': acc.role
        }
