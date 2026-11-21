"""Schemas de usuario y autenticación."""

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.common import SchemaBase


class UserCreate(SchemaBase):
    """Registro de usuario (RF-01): nombre de usuario y contraseña."""

    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$",
                          description="Nombre de usuario (3-50, letras, números y _).")
    # max 72: bcrypt solo usa los primeros 72 bytes de la contraseña.
    password: str = Field(min_length=8, max_length=72, description="Contraseña (8-72 caracteres).")

    model_config = ConfigDict(
        str_strip_whitespace=False,  # los espacios de la contraseña cuentan
        json_schema_extra={"examples": [{"username": "duro", "password": "secreto123"}]},
    )


class UserRead(BaseModel):
    """Usuario devuelto por la API. Nunca incluye la contraseña ni su hash."""

    id: int
    username: str

    model_config = ConfigDict(from_attributes=True)


class TokenPair(BaseModel):
    """Respuesta del login y del refresco (formato estándar OAuth2)."""

    access_token: str = Field(description="JWT para la cabecera Authorization: Bearer <token>.")
    refresh_token: str = Field(description="Token para pedir un access token nuevo en /auth/refresh.")
    token_type: str = Field(default="bearer")
    expires_in: int = Field(description="Segundos de validez del access token.")


class RefreshRequest(SchemaBase):
    refresh_token: str = Field(min_length=1)
