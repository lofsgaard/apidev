from fastapi import FastAPI, Depends
from typing import Annotated
from app.auth.router import router as auth_router
from app.auth.models import Users
from app.auth.auth import get_current_active_user

app = FastAPI()

app.include_router(auth_router, tags=["auth"])


@app.get("/")
async def read_main():
    return {"msg": "Hello World"}


@app.get("/users/me/items/")
async def read_own_items(
        current_user: Annotated[Users, Depends(get_current_active_user)]):
    return [{"item_id": "Foo", "owner": current_user.username}]
