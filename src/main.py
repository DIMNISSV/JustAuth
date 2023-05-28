from fastapi import FastAPI
from src.users.router import router
from src.models.database import database

app = FastAPI()
app.state.database = database

app.include_router(router, prefix="/users")


@app.on_event("startup")
async def startup() -> None:
    database_ = app.state.database
    if not database_.is_connected:
        await database_.connect()


@app.on_event("shutdown")
async def shutdown() -> None:
    database_ = app.state.database
    if database_.is_connected:
        await database_.disconnect()
