from fastapi import FastAPI, Depends, status, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from models import UserBase, UserInDB, User
import secrets

# 6.2
app = FastAPI()
security = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

users_db = {
    "David": UserInDB(username="David", hashed_password=pwd_context.hash("12345")),
}


def authenticate_user(creds: HTTPBasicCredentials = Depends(security)):
    user = users_db.get(creds.username)

    if user is None:
        fake_hash = pwd_context.hash("fake_password_for_timing_attack")
        pwd_context.verify(creds.password, fake_hash)
        secrets.compare_digest(creds.username, "fake_username")

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"})

    if not pwd_context.verify(creds.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"})

    if not secrets.compare_digest(creds.username, user.username):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"})

    return user


@app.post("/register", tags=["Register"])
def register(user: User):
    if user.username in users_db:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

    hashed_password = pwd_context.hash(user.password)
    new_user = UserInDB(username=user.username, hashed_password=hashed_password)
    users_db[user.username] = new_user
    return {"message": "User created successfully", "user": user.username}


@app.post("/login", tags=["Login"])
def login(user: UserInDB = Depends(authenticate_user)):
    return {"message": f"Welcome, {user.username}"}