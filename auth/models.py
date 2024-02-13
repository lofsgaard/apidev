from pydantic import BaseModel
from typing import Optional
from sqlmodel import SQLModel, Field, UniqueConstraint
from datetime import datetime


class UsersBase(SQLModel):
    username: str
    hashed_password: str


class Users(UsersBase, table=True):
    __table_args__ = (UniqueConstraint("username"),)
    id: Optional[int] = Field(primary_key=True, nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    disabled: bool | None = True


class UsersCreate(UsersBase):
    pass


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str

