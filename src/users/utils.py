from fastapi import Security, Depends, HTTPException
from fastapi_jwt import JwtAuthorizationCredentials


def auth_required(cns: JwtAuthorizationCredentials, admin_level: int = 0, subscribe_level: int = 0) -> None:
    if cns:
        if cns["admin_level"] < admin_level or cns["subscribe_level"] < subscribe_level:
            raise HTTPException(403)
    else:
        raise HTTPException(401)
