from fastapi.testclient import TestClient
from dotenv import load_dotenv, find_dotenv
import os

from app.main import app
from app.auth.auth import get_password_hash, verify_password

load_dotenv(find_dotenv())
username = str(os.environ.get('username'))
password = str(os.environ.get('password'))


client = TestClient(app)


async def test_get_password_hash():
    mypassword = 'password1234'
    assert await get_password_hash(mypassword) is not None


async def test_verify_password():
    mypassword = 'password1234'
    other_password = 'password12345'
    hashed_password = await get_password_hash(mypassword)
    assert await verify_password(mypassword, hashed_password.decode('utf-8')) is True
    assert await verify_password(other_password, hashed_password.decode('utf-8')) is False
