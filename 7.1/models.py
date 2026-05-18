from pydantic import BaseModel, EmailStr, Field, model_validator
from enum import Enum

class Permissions(str, Enum):
    """перечисление всех разрешений в системе"""
    READ_USERS = "read:users"
    WRITE_USERS = "write:users"
    DELETE_USERS = "delete:users"
    READ_ADMIN = "read:admin"
    WRITE_ADMIN = "write:admin"
    READ_REPORTS = "read:reports"
    WRITE_REPORTS = "write:reports"

class Role(BaseModel):
    """роль содержит название и список разрешений"""
    name: str
    permissions: list[str]


class User(BaseModel):
    username: str
    full_name: str | None = None
    email: EmailStr | None = None
    disabled: bool = False
    roles: list[str]
    permissions: set[str] = Field(default_factory=set)
    extra_permissions: list[str] = Field(default_factory=list)

    @model_validator(mode='after')
    def populate_permissions(self):
        """автоматически собираем все разрешения при создании пользователя"""
        from db import ROLES_REGISTRY

        # собираем все разрешения из ролей
        all_permissions = set()
        for role_name in self.roles:
            if role_name in ROLES_REGISTRY:
                role = ROLES_REGISTRY[role_name]
                all_permissions.update(role.permissions)

        # добавляем дополнительные разрешения
        all_permissions.update(self.extra_permissions)

        self.permissions = all_permissions
        return self

class UserLogin(BaseModel):
    """Модель для входа в систему"""
    username: str
    password: str