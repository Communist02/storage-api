import base64
import ssl
from typing import Any
from fastapi import Cookie, Depends, HTTPException, Query
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import httpx2
from config import config
import truststore


security = HTTPBearer(auto_error=False)


async def validate_token(token: str) -> dict[str, Any] | None:
    """
    Проверяет токен через сервис авторизации.
    Возвращает данные пользователя или None.
    """
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if config.client_cert_path and config.client_private_key_path:
        context.load_cert_chain(
            certfile=config.client_cert_path, keyfile=config.client_private_key_path)
    else:
        print("Client certificate or private key not provided. Skipping client certificate authentication.")

    async with httpx2.AsyncClient(verify=context) as client:
        response = await client.post(
            f'{config.auth_api_url}/introspect',
            headers={'Authorization': f'Bearer {token}'},
        )
    if response.status_code == 200:
        session = response.json()
        if session['active'] == True:
            session['user_key'] = base64.urlsafe_b64decode(
                session['user_key'].encode())
            return session


async def get_auth_status() -> dict[str, Any]:
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    status = {'host': config.auth_api_url.replace('http://', '').replace('https://', '').split(
        ':')[0], 'type': 'api', 'port': int(config.auth_api_url.split(':')[-1])}

    if config.client_cert_path and config.client_private_key_path:
        context.load_cert_chain(
            certfile=config.client_cert_path, keyfile=config.client_private_key_path)
    else:
        message = f"Client certificate or private key not provided"
        print(message)
        status['detail'] = message

    try:
        async with httpx2.AsyncClient(verify=context) as client:
            response = await client.get(
                f'{config.auth_api_url}/status'
            )

            if response.status_code == 200:
                return response.json() | status
            else:
                return {'status': 'failed'} | status
    except Exception as error:
        print(f"Error while checking auth service status: {error}")
        return {'status': 'failed', 'detail': status.get('detail', str(error))} | status


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    cookie_token: str | None = Cookie(None, alias="token"),
    query_token: str | None = Query(None, alias="token")
) -> dict[str, Any]:
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
