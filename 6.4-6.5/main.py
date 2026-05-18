from fastapi import FastAPI, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from typing import Dict
from config import settings
from models import UserInDB, User
import secrets
import jwt
import datetime

# 6.4 - 6.5
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
users_db = {
    "David": UserInDB(username="David", hashed_password=pwd_context.hash("12345")),
}


def create_token(data: Dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY.get_secret_value(), algorithm=settings.ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"})

    try:
        payload = jwt.decode(token, settings.SECRET_KEY.get_secret_value(), algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"})
    except jwt.InvalidTokenError:
        raise credentials_exception

    user = users_db.get(username)
    if user is None:
        raise credentials_exception

    return user


def auth_user(username: str, password: str) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"})

    db_user = users_db.get(username)

    if db_user is None:
        fake_hash = pwd_context.hash("fake_password")
        pwd_context.verify(password, fake_hash)
        secrets.compare_digest(username, "fake_username")
        raise credentials_exception
    if not pwd_context.verify(password, db_user.hashed_password):
        raise credentials_exception
    if not secrets.compare_digest(username, db_user.username):
        raise credentials_exception

    return db_user


# @app.post("/login", tags=["login"], summary="Login user")
# def login(user_in: User):
#     db_user = users_db.get(user_in.username)
#     if db_user is None or not pwd_context.verify(user_in.password, db_user.hashed_password):
#         raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
#     token = create_token({"sub": db_user.username})
#     return {"access_token": token, "token_type": "bearer"}

@app.post("/login", tags=["login"], summary="Login user with provided credentials")
def login(user_in: User):
    authenticated_user = auth_user(user_in.username, user_in.password)
    token = create_token({"sub": authenticated_user.username})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/register", tags=["register"], summary="Register user")
def register(user_in: User):
    user = users_db.get(user_in.username)
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,  # или 400 Bad Request
            detail="Username already exists")

    new_user = UserInDB(username=user_in.username, hashed_password=pwd_context.hash(user_in.password))
    users_db[user_in.username] = new_user

    return {"message": "User created successfully", "user": user_in.username}


@app.get("/protected_resource", tags=["protected"], summary="Protected resource")
def protected_resource(current_user: UserInDB = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}!"}
