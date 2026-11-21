"""Router del recurso /users."""

from fastapi import APIRouter

from app.core.deps import CurrentUser
from app.schemas import ErrorResponse, UserRead

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/me",
    response_model=UserRead,
    summary="Usuario actual",
    description="Devuelve el usuario del token (dependencias anidadas: get_current_user → oauth2_scheme + get_db).",
    responses={401: {"model": ErrorResponse, "description": "Sin token o token no válido"}},
)
def read_me(current_user: CurrentUser):
    return current_user
