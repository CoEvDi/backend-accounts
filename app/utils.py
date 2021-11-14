from passlib.hash import bcrypt
from jose import JWTError, jwt
from fastapi import Request

from .config import cfg
from .errors import HTTPabort


def hash_password(password):
    return bcrypt.hash(password)


def verify_password(password, hashed_password):
    return bcrypt.verify(password, hashed_password)


class CurrentUser:
    def __init__(self, account_id, role, session_id, client, login_time):
        self.account_id = account_id
        self.role = role
        self.session_id = session_id
        self.login_time = login_time
        self.client = client

    def jsonify_info(self, login, name, register_time):
        return {
            'session_id': self.session_id,
            'role': self.role,
            'account_id': self.account_id,
            'client': self.client,
            'login_time': self.login_time,
            'login': login,
            'name': name,
            'register_time': register_time
        }


async def get_current_user(request: Request):
    try:
        account_id = int(request.headers['COEVDI_ACCOUNT_ID'])
    except Exception as e:
        HTTPabort(401, 'Missing HEADER')

    session_id = request.headers['COEVDI_SESSION_ID']
    role = request.headers['COEVDI_ACCOUNT_ROLE']
    login_time = request.headers['COEVDI_LOGIN_TIME']
    client = request.headers['COEVDI_CLIENT']

    if not (account_id and session_id and role and login_time and client):
        HTTPabort(401, 'Missing HEADER')

    return CurrentUser(account_id, role, session_id, client, login_time)
