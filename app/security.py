from typing import Optional
from passlib.context import CryptContext
from starlette.authentication import AuthenticationBackend, AuthCredentials, SimpleUser
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.requests import HTTPConnection


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


class SessionAuthBackend(AuthenticationBackend):
    async def authenticate(self, conn: HTTPConnection):
        username = conn.session.get("username")
        role = conn.session.get("role")
        if not username:
            return
        return AuthCredentials(["authenticated", role or "user"]), SimpleUser(username)


def get_auth_middleware() -> AuthenticationMiddleware:
    return AuthenticationMiddleware(backend=SessionAuthBackend())



