from pydantic import BaseModel
from typing import Optional


class RegisterUser(BaseModel):
    login: str
    password: str
    name: str    


class Account(BaseModel):
    account_id: int


class ChangePassword(BaseModel):
    old_password: str
    new_password: str


class VerifyAccount(BaseModel):
    login: Optional[str] = None
    account_id: Optional[int] = None
    password: str
