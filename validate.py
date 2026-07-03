import base64
import ssl
from fastapi import Cookie, Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx
from config import config
import truststore


security = HTTPBearer(auto_error=False)


async def validate_token(token: str) -> dict | None:
    """
    Проверяет токен через сервис авторизации.
    Возвращает данные пользователя или None.
    """
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if config.client_cert and config.client_private_key:
        context.load_cert_chain(
            certfile=config.client_cert, keyfile=config.client_private_key)
    else:
        print("Client certificate or private key not provided. Skipping client certificate authentication.")

    async with httpx.AsyncClient(verify=False if not config.debug_mode else context) as client:
        response = await client.get(
            f'{config.auth_api_url}/introspect',
            headers={'Authorization': f'Bearer {token}'},
        )
    if response.status_code == 200:
        session = response.json()
        if session['active'] == True:
            session['hash1'] = base64.urlsafe_b64decode(
                session['hash1'].encode())
            session['hash2'] = base64.urlsafe_b64decode(
                session['hash2'].encode())
            session['jwt_token'] = session['jwt']
            return session


async def get_auth_status() -> dict:
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    async with httpx.AsyncClient(verify=False if not config.debug_mode else context) as client:
        response = await client.get(
            f'{config.auth_api_url}/status'
        )
        status = {'host': config.auth_api_url.replace('http://', '').replace(
            'https://', '').split(':')[0], 'type': 'api', 'port': config.auth_api_url.split(':')[-1]}
        if response.status_code == 200:
            return response.json() | status
        else:
            return {'status': 'failed'} | status


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    cookie_token: str | None = Cookie(None, alias="token"),
    query_token: str | None = Query(None, alias="token")
) -> dict:
    """
    Зависимость для получения текущего пользователя.
    Используется в защищенных маршрутах.
    """

    if query_token:
        token = query_token
    elif credentials and credentials.credentials:
        token = credentials.credentials
    elif cookie_token:
        token = cookie_token
    else:
        token = None

    if not token:
        raise HTTPException(
            status_code=401,
            detail="Access token is required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Валидируем токен
    user_data = await validate_token(token)

    if not user_data:
        raise HTTPException(
            status_code=401,
            detail="Token is invalid or expired",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user_data
