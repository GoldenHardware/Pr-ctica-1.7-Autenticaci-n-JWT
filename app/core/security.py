"""
Seguridad: hash de contraseñas (bcrypt) y tokens JWT (python-jose).

Contraseñas
-----------
Nunca se guardan en texto plano (RNF-01). Se guarda solo el hash bcrypt:

    $2b$12$i4sEuQdlzDaA1JFjVz0buu C4HwFcDSo.o8wYkuK.J6t0biP6ZpW/K
     |   |  |____ salt (22 car.) _||______ hash (31 car.) _______|
     |   +-- coste: 2^12 rondas
     +------ versión del algoritmo

- Salt único por usuario: bcrypt genera un salt aleatorio en cada hash, así que
  dos usuarios con la misma contraseña tienen hashes distintos y no sirven las
  tablas precalculadas (rainbow tables).
- Coste configurable (BCRYPT_ROUNDS): cada +1 duplica el tiempo de cálculo.

Tokens
------
- access token: JWT firmado con HS256, dura ACCESS_TOKEN_EXPIRE_MINUTES (30).
  Claims: sub (id del usuario), exp (caducidad), iat (emisión), type, jti.
- refresh token: JWT de larga duración (7 días) que solo sirve para pedir un
  access token nuevo en /auth/refresh. Se guarda su jti en la BD para poder
  revocarlo (logout) y rotarlo (cada uso lo invalida y emite otro).
"""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext

from app.core.config import (
    ACCESS_TOKEN_EXPIRE_MINUTES, BCRYPT_ROUNDS, ENVIRONMENT, JWT_ALGORITHM,
    REFRESH_TOKEN_EXPIRE_DAYS, SECRET_KEY,
)
from app.core.logging import logger

# --- Clave de firma -----------------------------------------------------------
if SECRET_KEY:
    _SECRET_KEY = SECRET_KEY
elif ENVIRONMENT == "production":
    raise RuntimeError("Falta la variable de entorno SECRET_KEY (obligatoria en producción)")
else:
    _SECRET_KEY = secrets.token_urlsafe(48)
    logger.warning("SECRET_KEY no definida: se usa una clave aleatoria. Los tokens dejarán de valer al reiniciar.")

# --- Contraseñas --------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=BCRYPT_ROUNDS)

# Hash de una contraseña cualquiera. Se usa para que el login tarde lo mismo
# exista o no el usuario (evita adivinar usuarios midiendo el tiempo de respuesta).
_DUMMY_HASH = pwd_context.hash("contraseña-que-no-existe")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str | None) -> bool:
    if hashed is None:
        pwd_context.verify(password, _DUMMY_HASH)  # mismo coste aunque el usuario no exista
        return False
    return pwd_context.verify(password, hashed)


# --- JWT ----------------------------------------------------------------------
class TokenError(Exception):
    """Token inválido. `expired` distingue un token caducado de uno manipulado/mal formado."""

    def __init__(self, expired: bool = False):
        self.expired = expired
        super().__init__("Token expirado" if expired else "Token inválido")


def _create_token(user_id: int, token_type: str, expires_delta: timedelta) -> tuple[str, str, datetime]:
    now = datetime.now(UTC)
    expire = now + expires_delta
    jti = uuid.uuid4().hex
    payload = {"sub": str(user_id), "type": token_type, "iat": now, "exp": expire, "jti": jti}
    return jwt.encode(payload, _SECRET_KEY, algorithm=JWT_ALGORITHM), jti, expire


def create_access_token(user_id: int) -> str:
    token, _, _ = _create_token(user_id, "access", timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return token


def create_refresh_token(user_id: int) -> tuple[str, str, datetime]:
    """Devuelve (token, jti, fecha de caducidad) para guardar el jti en la BD."""
    return _create_token(user_id, "refresh", timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))


def decode_token(token: str, expected_type: str) -> dict:
    """
    Verifica firma, caducidad (exp) y tipo. python-jose comprueba `exp`
    automáticamente y lanza ExpiredSignatureError si ya pasó.
    """
    try:
        # algorithms=[...] fijo: nunca se acepta el algoritmo que diga el token
        # (evita el ataque de cambiar "alg" a "none").
        payload = jwt.decode(token, _SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except ExpiredSignatureError as exc:
        raise TokenError(expired=True) from exc
    except JWTError as exc:
        raise TokenError() from exc
    if payload.get("type") != expected_type or not str(payload.get("sub", "")).isdigit():
        raise TokenError()
    return payload
