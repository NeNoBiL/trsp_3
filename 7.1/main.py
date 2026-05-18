from fastapi import FastAPI, Depends, HTTPException, status
from security import create_jwt_token
from models import UserLogin, User, Permissions
from db import USERS_DATA
from dependencies import get_current_user
from rbac import PermissionChecker

app = FastAPI()


@app.post("/login")
async def login(user_in: UserLogin):
    for user in USERS_DATA:
        if user["username"] == user_in.username and user["password"] == user_in.password:
            token = create_jwt_token({"sub": user_in.username})
            return {"access_token": token, "token_type": "bearer"}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неверные учетные данные")


@app.get("/admin")
@PermissionChecker([Permissions.READ_ADMIN])  # требуется разрешение read:admin
async def admin_info(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}! Welcome to the admin page."}


@app.get("/users")
@PermissionChecker([Permissions.READ_USERS])  # требуется разрешение read:users
async def read_users(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}! Here is the list of users."}


@app.post("/users")
@PermissionChecker([Permissions.WRITE_USERS])  # требуется разрешение write:users
async def write_users(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}! You can create/update users."}


@app.delete("/users/{user_id}")
@PermissionChecker([Permissions.DELETE_USERS])  # требуется разрешение delete:users
async def delete_users(user_id: int, current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}! You deleted user {user_id}."}


@app.get("/about_me")
async def about_me(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "roles": current_user.roles,
        "permissions": list(current_user.permissions)  # показываем все разрешения
    }

@app.get("/moderator")
@PermissionChecker([Permissions.READ_USERS,Permissions.WRITE_USERS,Permissions.READ_REPORTS])
async def moderator(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}! Welcome to the moderator page."}
