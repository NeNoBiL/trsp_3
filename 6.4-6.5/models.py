from pydantic import BaseModel, Field

class UserBase(BaseModel):
    username: str = Field(..., min_length=5, max_length=20, description='Username')


class User(UserBase):
    password: str = Field(..., min_length=5, max_length=30, description='Password')


class UserInDB(UserBase):
    hashed_password: str