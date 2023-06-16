from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, APIRouter
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt

from users import models

router = APIRouter()

# Некоторые настройки
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE = timedelta(minutes=30)
REFRESH_TOKEN_EXPIRE = timedelta(days=7)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/users/token")


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Функция для аутентификации пользователя
async def authenticate_user(username, password) -> models.User:
    user = await models.User.objects.get_or_none(username=username, password=password)
    if user:
        return user
    else:
        raise HTTPException(status_code=401, detail="Неправильные имя пользователя или пароль")


@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()) -> models.AuthRepr:
    user = await authenticate_user(form_data.username, form_data.password)
    access_token = create_access_token(
        data={"sub": user.pk,
              "admin_level": user.admin_level,
              "subscribe_level": user.subscribe_level},
        expires_delta=ACCESS_TOKEN_EXPIRE
    )
    refresh_token = create_access_token(
        data={"sub": user.pk},
        expires_delta=REFRESH_TOKEN_EXPIRE
    )
    return models.AuthRepr(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh_token")
async def refresh_token(refresh_token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        pk = payload.get("sub")
        if not pk:
            raise HTTPException(status_code=401, detail="Некорректные данные в токене обновления")
        new_access_token = create_access_token(
            data=payload,
            expires_delta=ACCESS_TOKEN_EXPIRE
        )
        return models.AuthRepr(access_token=new_access_token, refresh_token=refresh_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Некорректный токен обновления")
