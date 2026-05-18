from models import User, Role, Permissions

# реестр ролей с их разрешениями
ROLES_REGISTRY = {
    "admin": Role(
        name="admin",
        permissions=[
            Permissions.READ_ADMIN,
            Permissions.WRITE_ADMIN,
            Permissions.READ_USERS,
            Permissions.WRITE_USERS,
            Permissions.DELETE_USERS,
            Permissions.READ_REPORTS,
            Permissions.WRITE_REPORTS,
        ]
    ),
    "user": Role(
        name="user",
        permissions=[
            Permissions.READ_USERS,
            Permissions.READ_REPORTS,
        ]
    ),
    "moderator": Role(
        name="moderator",
        permissions=[
            Permissions.READ_USERS,
            Permissions.WRITE_USERS,
            Permissions.READ_REPORTS,
            Permissions.WRITE_REPORTS,
        ]
    ),
}

USERS_DATA = [
    {
        "username": "alice",
        "password": "pass123",
        "full_name": "Alice Admin",
        "email": "alice@example.com",
        "roles": ["admin"],
        "extra_permissions": []
    },
    {
        "username": "bob",
        "password": "pass456",
        "full_name": "Bob User",
        "email": "bob@example.com",
        "roles": ["user"],
        "extra_permissions": []
    },
    {
        "username": "david",
        "password": "kudar",
        "full_name": "David User",
        "email": "david@example.com",
        "roles": ["moderator"],
        "extra_permissions": []
    },
]


def get_user(username: str) -> User | None:
    """Получаем пользователя по имени (без пароля)"""
    for user_data in USERS_DATA:
        if user_data["username"] == username:
            return User(**{k: v for k, v in user_data.items() if k != "password"})
    return None
