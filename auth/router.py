from dotenv import load_dotenv, find_dotenv
import os
from datetime import timedelta
from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from typing import Annotated
from sqlmodel.ext.asyncio.session import AsyncSession

from .auth import authenticate_user, create_access_token, get_current_active_user, get_password_hash
from .models import Token, Users, UsersBase
from db.database import get_session


load_dotenv(find_dotenv())

router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES'))


@router.post("/token")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(data={"sub": user[0].username}, expires_delta=access_token_expires)
    return Token(access_token=access_token, token_type="bearer")


@router.get("/users/me/", response_model=Users)
async def read_users_me(current_user: Annotated[Users, Depends(get_current_active_user)]):
    print(current_user)
    return current_user


@router.post("/users/create")
async def create_user(username: str, password: str, session: AsyncSession = Depends(get_session), logged_in = Depends(get_current_active_user)) -> UsersBase:
    hashed_password = await get_password_hash(password)
    user = Users(username=username, hashed_password=hashed_password)
    session.add(user)
    await session.commit()
    return user