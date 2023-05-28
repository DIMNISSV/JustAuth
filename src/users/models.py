import ormar
from decouple import config
from fastapi import Request
from pydantic import BaseModel

from src.models.database import BaseMeta


class AuthRepr(BaseModel):
    access_token: str
    refresh_token: str


class User(ormar.Model):
    """
    access_level, can be:
    levels: Ads Admin Moderator Subscribe

    """

    class Meta(BaseMeta):
        tablename = "users"

    pk: int = ormar.Integer(primary_key=True)
    name: str = ormar.String(max_length=32, unique=True)
    password: str = ormar.String(max_length=128, encrypt_secret=config("PASSWORD_SECRET"),
                                 encrypt_backend=ormar.EncryptBackends.HASH)
    admin_level: ormar.JSON[dict] = ormar.JSON(default={"everywhere": 0})  # 1 - moder; 2 - admin; 3 - super_admin
    subscribe_level: ormar.JSON[dict] = ormar.JSON(default={"everywhere": 0})

    def get_access_level(self, site: str | Request):
        return {
            key: getattr(self, key).get(
                site.url.hostname if isinstance(site, Request) else site,
                getattr(self, key).get("everywhere", 0)
            )
            for key in ("admin_level", "subscribe_level")
        }


UserLogin = User.get_pydantic(include={"name", "password"})
UserRepr = User.get_pydantic(exclude={"password"})
