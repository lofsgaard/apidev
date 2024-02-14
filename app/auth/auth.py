from dotenv import load_dotenv, find_dotenv
import os
import bcrypt
from fastapi import Depends, HTTPException, status
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import select
from jose import JWTError, jwt
from .models import Users, TokenData
from db.database import async_session
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status

load_dotenv(find_dotenv())



SECRET_KEY = str(os.environ.get('SECRET_KEY'))
ALGORITHM = str(os.environ.get('ALGORITHM'))
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get('ACCESS_TOKEN_EXPIRE_MINUTES'))


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



async def verify_password(plain_password: str, hashed_password: str):
    # Verify if the input password matches the hashed password
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


async def get_password_hash(password: str):
    # Generate a salt and hash the password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


async def get_user(username: str):
    async with async_session() as session:
        user = await session.execute(select(Users).where(Users.username == username))
        user = user.scalars().all()
        if user:
            return user


async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not await verify_password(password, user[0].hashed_password):
        return False
    return user


async def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user[0]


async def get_current_active_user(current_user: Annotated[Users, Depends(get_current_user)]):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user