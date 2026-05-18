import jwt
import datetime
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException, status, Depends

bearer_scheme = HTTPBearer()

# Секретный ключ для подписи JWT
# В реальном проекте храните его в .env файле, а не в коде!
SECRET_KEY = "mysecretkey"  # Генерируем через `openssl rand -hex 32`
ALGORITHM = "HS256"  # Используем HMAC SHA-256 для подписи
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Время жизни токена (15 минут)

def create_jwt_token(data: dict):
    """Создаём JWT-токен с указанием времени истечения"""
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})  # Добавляем время истечения в токен
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_from_token(creds: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    """Получаем информацию о пользователе из токена"""
    try:
        payload = jwt.decode(creds.credentials, SECRET_KEY, algorithms=[ALGORITHM])  # Декодируем токен
        return payload.get("sub")  # JWT-токен содержит `sub` (subject) — имя пользователя
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Токен устарел")  # Токен просрочен
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Ошибка авторизации")  # Невалидный токен