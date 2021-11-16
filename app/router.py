from fastapi import APIRouter, Depends, Response, Query
from fastapi.responses import JSONResponse
from typing import Optional, List

from . import schemas
from . import logic
from .utils import get_current_user


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
    data = await logic.me(current_user)
    return HTTPanswer(200, data)


@router.get('/account/{login}')
async def get_account(login: str):
    data = await logic.get_account_info(login)
    return HTTPanswer(200, data)


@router.get('/all')
async def get_all_accounts(offset: Optional[int] = Query(None), limit: Optional[int] = Query(None), role: Optional[str] = Query(None)):
    data = await logic.get_all_accounts(offset, limit, role)
    return HTTPanswer(200, data)


@router.post('/change_password')
async def change_password(passwords: schemas.ChangePassword, current_user = Depends(get_current_user)):
    await logic.change_password(current_user, passwords.old_password, passwords.new_password)
    return HTTPanswer(200, 'Successfully changed password')


# internal routes for auth micro-service

@router.post('/verify_account')
async def verify_account(account: schemas.VerifyAccount):
    data = await logic.verify_account(account)
    return HTTPanswer(200, data)
