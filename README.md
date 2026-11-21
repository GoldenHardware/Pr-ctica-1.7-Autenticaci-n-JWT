# Práctica 1.7 – Autenticación JWT

## Objetivo

Proteger la API con autenticación basada en tokens: registro, login con JWT, y que todos los endpoints de escritura (POST/PUT/DELETE) exijan un token válido que caduca a los 30 minutos.

## Archivos nuevos o modificados

```
app/
├── core/
│   ├── config.py      # + SECRET_KEY, ACCESS_TOKEN_EXPIRE_MINUTES (30), REFRESH_TOKEN_EXPIRE_DAYS, BCRYPT_ROUNDS
│   ├── security.py    # NUEVO: bcrypt (passlib) y JWT (python-jose)
│   ├── deps.py        # get_current_user con OAuth2PasswordBearer
│   └── errors.py      # + AuthError: 401 con cabecera WWW-Authenticate
├── models/models.py   # User (username, hashed_password) + RefreshToken
├── schemas/user.py    # UserCreate, UserRead, TokenPair, RefreshRequest
└── routers/
    ├── auth.py        # NUEVO: /auth/register, /auth/login, /auth/refresh, /auth/logout
    ├── users.py       # /users/me con el token
    ├── tasks.py       # POST/PUT/DELETE protegidos
    ├── projects.py    # POST/PUT/DELETE protegidos
    └── categories.py  # POST/PUT/DELETE protegidos
requirements.txt       # + passlib, bcrypt, python-jose[cryptography], python-multipart
```

## 1. Endpoints de autenticación

| Método | Ruta | Qué hace | Respuesta |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Crea un usuario. La contraseña se guarda hasheada con bcrypt | 201 / 409 / 422 |
| POST | `/api/v1/auth/login` | Comprueba las credenciales y devuelve `access_token` + `refresh_token` | 200 / 401 |
| POST | `/api/v1/auth/refresh` | Cambia un refresh token por un par nuevo (rotación) | 200 / 401 |
| POST | `/api/v1/auth/logout` | Revoca el refresh token | 204 |
| GET | `/api/v1/users/me` | Usuario del token | 200 / 401 |

El login usa el formulario estándar de OAuth2 (`OAuth2PasswordRequestForm`: `username` y `password` como form-data). Por eso funciona directamente con el botón **Authorize** de Swagger.

Respuesta del login:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

## 2. Endpoints protegidos

Todos los **POST, PUT y DELETE** de `tasks`, `projects` y `categories` exigen la cabecera `Authorization: Bearer <access_token>`. Los GET siguen siendo públicos.

```python
AUTH = [Depends(get_current_user)]

@router.post("", dependencies=AUTH, ...)
def create_task(...):
```

Incluyo también las categorías, porque el documento del proyecto (RF-07) dice que ninguna creación, edición o borrado de proyectos, tareas **o categorías** puede hacerse sin sesión.

### Dependencias anidadas

```
endpoint  →  get_current_user  →  oauth2_scheme   (lee "Authorization: Bearer ...")
                               →  get_db          (carga el usuario de la BD)
```

`get_current_user` comprueba la firma del token, que no haya caducado (`exp`) y que sea un access token. Después carga el usuario de la base de datos y, si algo falla, devuelve **401**.

## 3. Contraseñas: bcrypt con passlib

```python
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
```

Ejemplo de lo que se guarda en `users.hashed_password`:

```
$2b$12$eXNvz5de8PudWbijCZ4lQeH.jFpFw6B4fH/fU1gzZdU68Yjc1r0mm
 │   │  └─ salt (22 caracteres) ──┘└──── hash (31 caracteres) ───┘
 │   └─ coste: 2^12 = 4096 rondas
 └─ versión de bcrypt
```

- **Nunca se guarda en texto plano** (RNF-01): solo el hash, del que no se puede sacar la contraseña.
- **Salt único por usuario:** bcrypt genera un salt aleatorio en cada hash. Dos usuarios con la misma contraseña tienen hashes distintos, así que las tablas precalculadas (*rainbow tables*) no sirven.
- **Coste 12:** cada hash tarda unos 0,25 s. El usuario no lo nota al hacer login, pero quien quiera probar millones de contraseñas tardaría años. Cada +1 de coste duplica el tiempo, y se puede subir con `BCRYPT_ROUNDS` cuando los ordenadores sean más rápidos.
- La contraseña tiene un máximo de 72 caracteres, porque bcrypt ignora lo que pasa de 72 bytes.
- `bcrypt==4.0.1` está fijado porque passlib 1.7.4 no funciona con bcrypt 4.1 o superior.

## 4. JWT con python-jose

Contenido (*payload*) de un access token:

```json
{ "sub": "1", "type": "access", "iat": 1794299617, "exp": 1794301417, "jti": "c257c5358528..." }
```

| Claim | Para qué |
|---|---|
| `sub` | Id del usuario |
| `exp` | Caducidad: 30 minutos después de emitirlo. python-jose lo comprueba solo al decodificar |
| `iat` | Momento de emisión |
| `type` | `access` o `refresh`, para que no se pueda usar un refresh token como access token |
| `jti` | Identificador único (necesario para revocar refresh tokens) |

- Se firma con **HS256** y la clave `SECRET_KEY`, que se lee de una variable de entorno y **nunca está en el código** (RNF-12). En desarrollo, si no se define, se genera una aleatoria al arrancar. En producción es obligatoria y la app no arranca sin ella.
- Al decodificar se fija `algorithms=["HS256"]`. Así nunca se acepta el algoritmo que diga el propio token, lo que evita el ataque de poner `"alg": "none"`.

### Refresh token y rotación

El access token dura poco (30 min) para que, si alguien lo roba, le sirva poco tiempo. Para no obligar a escribir la contraseña cada media hora existe el **refresh token** (dura 7 días), que solo sirve para pedir un par nuevo en `/auth/refresh`.

- **Rotación:** cada vez que se usa un refresh token, se revoca y se emite otro nuevo. Su `jti` se guarda en la tabla `refresh_tokens`.
- **Detección de reutilización:** si alguien presenta un refresh token que ya se usó, es señal de que lo han robado. En ese caso se revocan **todas** las sesiones del usuario y se devuelve `TOKEN_REUSED`.
- **Logout:** revoca el refresh token (RF-06).

## 5. Errores 401

Todas las respuestas 401 llevan la cabecera **`WWW-Authenticate: Bearer`**, como manda el estándar HTTP, y un `error_code` distinto según la causa:

| `error_code` | Cuándo | Cabecera |
|---|---|---|
| `NOT_AUTHENTICATED` | No se envía token | `WWW-Authenticate: Bearer` |
| `TOKEN_EXPIRED` | El token ha caducado | `WWW-Authenticate: Bearer error="invalid_token"` |
| `INVALID_TOKEN` | Token manipulado, mal formado, de otro tipo o de un usuario borrado | `WWW-Authenticate: Bearer error="invalid_token"` |
| `INVALID_CREDENTIALS` | Login con usuario o contraseña incorrectos | `WWW-Authenticate: Bearer` |
| `TOKEN_REUSED` | Se reutiliza un refresh token ya usado | `WWW-Authenticate: Bearer error="invalid_token"` |

`TOKEN_EXPIRED` va separado para que el frontend sepa que tiene que renovar el token o volver al login, en lugar de mostrar un error genérico.

## 6. Decisiones de seguridad

| Decisión | Por qué |
|---|---|
| **Mensaje de login genérico:** "Usuario o contraseña incorrectos" | No revela si el usuario existe (RF-04). Si dijera "el usuario no existe", un atacante podría sacar la lista de usuarios. |
| **Mismo tiempo de respuesta exista o no el usuario** | Si el usuario no existe se calcula igualmente un hash bcrypt de mentira. Así no se puede adivinar si existe midiendo cuánto tarda la respuesta. |
| **El registro sí dice "el nombre de usuario ya existe"** | Lo pide el RF-02. Es un riesgo aceptado: revela que el nombre está cogido, igual que pasa en cualquier web al registrarse. Para mitigarlo en un entorno real se limitaría el número de intentos (*rate limiting*). |
| **Access token corto (30 min) + refresh token** | Equilibrio entre seguridad (un token robado caduca pronto) y comodidad (no hay que repetir el login). |
| **GET públicos** | El enunciado pide proteger la escritura. Proteger también la lectura sería cambiar `dependencies` en los GET. |
| **Sin roles** | El documento del proyecto deja los roles fuera del alcance base (RBAC es el "Reto 1.5"): todos los usuarios autenticados pueden hacer lo mismo. |

### Análisis de amenazas

| Amenaza | Cómo se mitiga |
|---|---|
| Robo de la base de datos | Solo hay hashes bcrypt con salt y coste 12. No se pueden revertir, y probar contraseñas es muy lento. |
| Fuerza bruta contra el login | bcrypt hace que cada intento cueste unos 0,25 s, y los fallos quedan en el log (`Login fallido para el usuario ...`). Mejora pendiente: limitar intentos por IP. |
| Enumeración de usuarios | Mensaje genérico y mismo tiempo de respuesta en el login. |
| Token manipulado (cambiar `sub` a otro usuario) | La firma HS256 deja de coincidir → `INVALID_TOKEN`. |
| Ataque `alg: none` | El algoritmo está fijado al decodificar. |
| Robo de un access token | Caduca en 30 minutos. |
| Robo de un refresh token | Rotación y detección de reutilización: al primer uso doble se cierran todas las sesiones. Además, logout lo revoca. |
| Clave de firma filtrada en Git | `SECRET_KEY` va por variable de entorno, nunca en el código. |
| Token interceptado en la red | En despliegue se usará HTTPS (RNF-02). En local va por HTTP. |
| Stacktrace con información interna | El handler global de la práctica 1.4 nunca lo muestra al cliente. |
