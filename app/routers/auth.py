"""
Router /auth: registro, login, refresco y cierre de sesión.

POST /auth/register   crea un usuario (contraseña hasheada con bcrypt)
POST /auth/login      comprueba credenciales y devuelve access + refresh token
POST /auth/refresh    cambia un refresh token por un par nuevo (rotación)
POST /auth/logout     revoca el refresh token
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update

from app.core.config import ACCESS_TOKEN_EXPIRE_MINUTES
from app.core.deps import DbSession
from app.core.errors import AuthError, ConflictError
from app.core.logging import logger
from app.core.security import (
    TokenError, create_access_token, create_refresh_token, decode_token, hash_password, verify_password,
)
from app.models import RefreshToken, User
from app.schemas import ErrorResponse, RefreshRequest, TokenPair, UserCreate, UserRead

router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    responses={422: {"model": ErrorResponse, "description": "Datos no válidos"}},
)

UNAUTHORIZED = {401: {"model": ErrorResponse, "description": "Credenciales o token no válidos"}}


def _issue_tokens(db: DbSession, user_id: int) -> TokenPair:
    """Crea un access token y un refresh token, y guarda el jti del refresh en la BD."""
    refresh, jti, expires_at = create_refresh_token(user_id)
    db.add(RefreshToken(jti=jti, user_id=user_id, expires_at=expires_at.replace(tzinfo=None)))
    db.commit()
    return TokenPair(
        access_token=create_access_token(user_id),
        refresh_token=refresh,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar un usuario",
    responses={409: {"model": ErrorResponse, "description": "Nombre de usuario ya existente"}},
)
def register(data: UserCreate, db: DbSession):
    if db.scalar(select(User.id).where(User.username == data.username)) is not None:
        # RF-02 obliga a informar del motivo (ver "Decisiones de seguridad" en el README).
        raise ConflictError("USERNAME_TAKEN", "El nombre de usuario ya existe")
    user = User(username=data.username, hashed_password=hash_password(data.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post(
    "/login",
    response_model=TokenPair,
    summary="Iniciar sesión",
    description=(
        "Formulario OAuth2 (`username` y `password` como form-data). Devuelve un access token "
        f"válido {ACCESS_TOKEN_EXPIRE_MINUTES} min y un refresh token. Si falla, el mensaje es "
        "el mismo exista o no el usuario."
    ),
    responses=UNAUTHORIZED,
)
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], db: DbSession):
    user = db.scalar(select(User).where(User.username == form.username))
    # verify_password tarda lo mismo aunque el usuario no exista (no se puede
    # adivinar si existe midiendo el tiempo de respuesta).
    if not verify_password(form.password, user.hashed_password if user else None):
        logger.warning("Login fallido para el usuario '%s'", form.username)
        # RF-04: mensaje genérico, no dice si falla el usuario o la contraseña.
        raise AuthError("INVALID_CREDENTIALS", "Usuario o contraseña incorrectos")
    return _issue_tokens(db, user.id)


@router.post(
    "/refresh",
    response_model=TokenPair,
    summary="Renovar el access token",
    description=(
        "Cambia un refresh token válido por un par nuevo. El refresh token usado queda revocado "
        "(rotación). Si se intenta reutilizar uno ya usado, se revocan todas las sesiones del usuario."
    ),
    responses=UNAUTHORIZED,
)
def refresh(data: RefreshRequest, db: DbSession):
    try:
        payload = decode_token(data.refresh_token, expected_type="refresh")
    except TokenError as exc:
        raise AuthError("TOKEN_EXPIRED" if exc.expired else "INVALID_TOKEN", str(exc), "invalid_token") from exc

    stored = db.get(RefreshToken, payload["jti"])
    if stored is None:
        raise AuthError("INVALID_TOKEN", "Token no válido", "invalid_token")
    if stored.revoked:
        # Reutilizar un refresh token ya rotado = posible robo: se cierran todas las sesiones.
        db.execute(update(RefreshToken).where(RefreshToken.user_id == stored.user_id).values(revoked=True))
        db.commit()
        logger.warning("Reutilización de refresh token del usuario %s: sesiones revocadas", stored.user_id)
        raise AuthError("TOKEN_REUSED", "Token ya utilizado; por seguridad se han cerrado todas las sesiones",
                        "invalid_token")

    stored.revoked = True  # rotación: este refresh token ya no se puede volver a usar
    return _issue_tokens(db, stored.user_id)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Cerrar sesión",
    description="Revoca el refresh token (RF-06). El access token deja de valer como mucho al caducar.",
)
def logout(data: RefreshRequest, db: DbSession):
    try:
        payload = decode_token(data.refresh_token, expected_type="refresh")
        stored = db.get(RefreshToken, payload["jti"])
        if stored is not None:
            stored.revoked = True
            db.commit()
    except TokenError:
        pass  # cerrar sesión con un token ya caducado o inválido no es un error
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# Limpieza: los refresh tokens caducados no sirven para nada.
def purge_expired_refresh_tokens(db) -> int:
    from sqlalchemy import delete

    result = db.execute(delete(RefreshToken).where(RefreshToken.expires_at < datetime.now(UTC).replace(tzinfo=None)))
    db.commit()
    return result.rowcount
