from datetime import timedelta

import ormar
from decouple import config
from fastapi import APIRouter, Security, HTTPException, Request, Response
from fastapi_jwt import JwtAccessBearerCookie, JwtAuthorizationCredentials, JwtRefreshBearer
from ormar.exceptions import AsyncOrmException

from src.users import models, utils

router = APIRouter()

access_security = JwtAccessBearerCookie(
    secret_key=config("SECRET"),
    auto_error=False,
    access_expires_delta=timedelta(minutes=15)
)

refresh_security = JwtRefreshBearer(
    secret_key=config("SECRET"),
    auto_error=True
)


@router.post("/auth")
async def auth(request: Request, user: models.UserLogin) -> models.AuthRepr:
    if not (user := await models.User.objects.get_or_none(**user.dict())):
        raise HTTPException(401)

    subject = {
        "pk": user.pk,
        **user.get_access_level(request)
    }
    access_token = access_security.create_access_token(subject=subject)
    refresh_token = refresh_security.create_refresh_token(subject=subject)

    return models.AuthRepr(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh")
def refresh(cns: JwtAuthorizationCredentials = Security(refresh_security)) -> models.AuthRepr:
    access_token = access_security.create_access_token(cns.subject)
    refresh_token = refresh_security.create_refresh_token(cns.subject, timedelta(days=2))

    return models.AuthRepr(access_token=access_token, refresh_token=refresh_token)


@router.post("/create")
async def create_new(user: models.UserLogin) -> models.UserRepr:
    return await models.User(**user.dict()).save()


@router.delete("/delete")
async def delete(pk: int = None, cns: JwtAuthorizationCredentials = Security(access_security)):
    utils.auth_required(cns)
    if not pk:
        pk = cns["pk"]
    elif pk != cns["pk"]:
        utils.auth_required(cns, 1)
    if user := await models.User.objects.get_or_none(pk=pk):
        try:
            await user.delete()
            return Response(f"User {pk} was deleted.")
        except AsyncOrmException as e:
            raise HTTPException(400, detail=e)
    else:
        raise HTTPException(404)


@router.get("/")
def get_filter(filter_connector: str = "and", filter_params: dict[str, str] = None,
               cns: JwtAuthorizationCredentials = Security(access_security)) -> list[models.UserRepr]:
    utils.auth_required(cns, 1)
    filter_connector = ormar.and_ if filter_connector == "and" else ormar.or_
    return [models.UserRepr(filter_connector(**user.dict())) for user in models.User.objects.filter(**filter_params)]


@router.get("/me")
def read_current(cns: JwtAuthorizationCredentials = Security(access_security)) -> models.UserRepr:
    utils.auth_required(cns)

    return models.UserRepr(pk=cns["pk"])
