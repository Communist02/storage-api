import ssl
from fastapi import HTTPException
import httpx
import xml.etree.ElementTree as ET
import truststore
from config import config


async def get_sts_token(token: str, endpoint: str, duration=2592000) -> dict | None:
    try:
        async with httpx.AsyncClient(verify=False if not config.debug_mode else truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)) as client:
            response = await client.post(
                f'{endpoint}/{f"?DurationSeconds={duration}" if duration != 0 else ""}',
                params={'Action': 'AssumeRoleWithWebIdentity',
                        'WebIdentityToken': token, 'Version': '2011-06-15'},
                timeout=15
            )
    except httpx.TimeoutException as e:
        raise HTTPException(
            status_code=500,
            detail={
                'error': 'Timeout',
                'message': "Couldn't get the STS token"
            }
        )

    if response.status_code == 200:
        xml_response = response.text
        # print(response.text)
        root = ET.fromstring(xml_response)
        access_key = root.find(
            './/{https://sts.amazonaws.com/doc/2011-06-15/}AccessKeyId')
        secret_key = root.find(
            './/{https://sts.amazonaws.com/doc/2011-06-15/}SecretAccessKey')
        session_token = root.find(
            './/{https://sts.amazonaws.com/doc/2011-06-15/}SessionToken')
        if access_key is not None and secret_key is not None and session_token is not None:
            credentials = {
                'access_key': access_key.text,
                'secret_key': secret_key.text,
                'session_token': session_token.text,
            }
            return credentials
    else:
        print('Ошибка получения STS токена:', response.status_code)
        if config.debug_mode:
            print(token)
            print(response.text)
            print(response.status_code)
