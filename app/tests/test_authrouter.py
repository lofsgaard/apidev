from fastapi.testclient import TestClient
from app.main import app
from dotenv import load_dotenv, find_dotenv
import os

load_dotenv(find_dotenv())
username = str(os.environ.get('username'))
password = str(os.environ.get('password'))


client = TestClient(app)


def test_token_withlogin():
    response = client.post("/token", data={"username": username, "password": password})
    assert response.status_code == 200
