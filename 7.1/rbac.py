from fastapi import HTTPException, status
from functools import wraps

class PermissionChecker:
    """декоратор для проверки разрешений пользователя"""
    def __init__(self, required_permissions: list[str]):
        self.required_permissions = required_permissions  # теперь это разрешения, а не роли

    def __call__(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            user = kwargs.get("current_user")
            if not user:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Требуется аутентификация")

            if not any(perm in user.permissions for perm in self.required_permissions):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Недостаточно прав для доступа. Требуется одно из разрешений: {', '.join(self.required_permissions)}"
                )

            return await func(*args, **kwargs)
        return wrapper