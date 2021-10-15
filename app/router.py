from fastapi import APIRouter, Depends, Response, Query
from fastapi.responses import JSONResponse
from typing import Optional, List

from . import schemas
from . import logic
from .butils import get_current_user


router = APIRouter()


def HTTPanswer(status_code, description):
    return JSONResponse(
        status_code=status_code,
        content={'content': description},
    )


# external routes for manage accounts

@router.post('/register')
async def register_user(user: schemas.RegisterUser):
    await logic.register_account(user.login, user.password, user.name)
    return HTTPanswer(201, 'User was registered')


@router.get('/me')
async def get_me(current_user = Depends(get_current_user)):
    return await logic.me(current_user)


@router.get('/{login}')
async def get_account(login: str):
    return await logic.get_account(login)


@router.get('/all')
async def get_all_accounts(offset: Optional[int] = Query(None), limit: Optional[int] = Query(None), role: Optional[string] = Query(None)):
    return await logic.get_all_accounts(offset, limit, role)


@router.post('/change_password')
async def change_password(passwords: schemas.ChangePassword, current_user = Depends(get_current_user)):
    await logic.change_password(current_user, passwords.old_password, passwords.new_password)
    return HTTPanswer(200, 'Successfully changed password')


# internal routes for auth micro-service

@router.post('/verify_account')
async def verify_account(account: schemas.VerifyAccount):
    return await logic.verify_account(account)
