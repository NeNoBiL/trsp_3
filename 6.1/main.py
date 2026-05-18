from fastapi import FastAPI, Depends, status, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from models import UserBase, UserInDB, User

# 6.1
app = FastAPI()
security = HTTPBasic()

users_db = {
    "David": User(username="David", password="12345"),
}


def authenticate_user(creds: HTTPBasicCredentials = Depends(security)):
    user = users_db.get(creds.username)
    if not user or user.password != creds.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"}
        )
    return user


@app.get("/login", tags=["Login"], summary="Login user")
async def login(user: User = Depends(authenticate_user)):
    return {"message": f"Welcome, {user.username}!"}