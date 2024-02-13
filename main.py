from fastapi import FastAPI
from auth import router as auth


app = FastAPI()

app.include_router(auth.router, tags=["auth"])

