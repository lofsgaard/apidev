from fastapi import FastAPI, Depends
from typing import Annotated
from auth import router as auth
from auth.models import Users
from auth.auth import get_current_active_user


app = FastAPI()

app.include_router(auth.router, tags=["auth"])


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[Users, Depends(get_current_active_user)]):
    return [{"item_id": "Foo", "owner": current_user.username}]