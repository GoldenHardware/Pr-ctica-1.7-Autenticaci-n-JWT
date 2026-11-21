"""
Dependencias reutilizables de FastAPI.

Cadena de dependencias ANIDADAS de un endpoint protegido:

    endpoint  ->  get_current_user  ->  oauth2_scheme   (lee "Authorization: Bearer <token>")
                                    ->  get_db          (sesión de BD para cargar el usuario)

FastAPI las resuelve solo y, si el endpoint también pide get_db, reutiliza la
MISMA sesión dentro de la petición.
"""

from typing import Annotated

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import API_V1_PREFIX
from app.core.database import get_db
from app.core.errors import AuthError
from app.core.security import TokenError, decode_token
from app.models import User

# Alias para no repetir "Session = Depends(get_db)" en cada endpoint.
DbSession = Annotated[Session, Depends(get_db)]

# Lee el token de la cabecera Authorization. tokenUrl hace que Swagger muestre
# el botón "Authorize" con un formulario de usuario/contraseña.
# auto_error=False: si falta el token lo gestionamos nosotros para devolver
# nuestro formato de error (con error_code) en lugar del genérico de FastAPI.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{API_V1_PREFIX}/auth/login", auto_error=False)


def get_current_user(db: DbSession, token: Annotated[str | None, Depends(oauth2_scheme)]) -> User:
    """Devuelve el usuario del token o lanza 401 (con WWW-Authenticate: Bearer)."""
    if not token:
        raise AuthError("NOT_AUTHENTICATED", "Se necesita iniciar sesión (falta el token)")
    try:
        payload = decode_token(token, expected_type="access")
    except TokenError as exc:
        if exc.expired:
            raise AuthError("TOKEN_EXPIRED", "La sesión ha caducado, vuelve a iniciar sesión", "invalid_token") from exc
        raise AuthError("INVALID_TOKEN", "Token no válido", "invalid_token") from exc

    user = db.get(User, int(payload["sub"]))
    if user is None:  # p. ej. el usuario se borró después de emitir el token
        raise AuthError("INVALID_TOKEN", "Token no válido", "invalid_token")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
