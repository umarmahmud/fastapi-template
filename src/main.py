from fastapi import FastAPI
from .auth.auth import router as auth_router
from .logger import configure_logging

configure_logging()

app = FastAPI()

app.include_router(auth_router)


@app.get("/")
def read_root():
    return { "msg": "Hello, World!" }

