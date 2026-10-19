from typing import Literal
from pydantic import BaseModel
from config import config, default_config
import httpx2


class CheckStatus(BaseModel):
    name: str
    status: Literal['success', 'fail', 'warning'] = 'fail'
    detail: str = ''


def check_config(key: str, fail_text: str = '', success_text: str = '', name: str | None = None, is_warning: bool = False) -> CheckStatus:
    is_fail = config.get(key) == default_config.get(key) or not config.get(key)
    if name is None:
        name = f'[{key}] указан в конфиге'
    fail_status = 'fail' if not is_warning else 'warning'
    return CheckStatus(name=name, status=fail_status if is_fail else 'success', detail=fail_text if is_fail else success_text)


async def check_url(url: str, fail_text: str = '', success_text: str = '', name: str | None = None) -> CheckStatus:
    async with httpx2.AsyncClient() as client:
        try:
            response = await client.get(url)
            success_text = f'Подключение к {url} проходит успешно'
        except httpx2.ConnectError:
            response = None
        except httpx2.UnsupportedProtocol as error:
            response = None
            fail_text = str(error)
    is_fail = response is None or response.status_code != 200
    if name is None:
        name = f'url: {url} доступен для подключения'
    return CheckStatus(name=name, status='fail' if is_fail else 'success', detail=fail_text if is_fail else success_text)


async def get_checklist() -> list[CheckStatus]:
    from main import database
    from main import opensearch
    from main import s3
    status: list[CheckStatus] = []
    database_status = database.get_status()
    opensearch_status = await opensearch.get_status()
    s3_status = await s3.get_status()

    status.append(check_config(
        'db_host', 'Необходимо указать в конфиге хост базы данных'))
    status.append(CheckStatus(name='Подключено к базе данных', status='fail' if database_status['status'] != 'active' else 'success', detail=str(
        database_status.get('detail', ''))))
    status.append(check_config(
        'auth_api_url', 'Необходимо указать адрес центра авторизации в конфиге'))
    status.append(await check_url(config.auth_api_url + '/.well-known/openid-configuration', 'Указанный [auth_api_url] не доступен для подключения', name='[auth_api_url] доступен для подключения'))
    status.append(check_config(
        'client_cert_path', 'Необходимо указать в конфиге путь до сертификата агента'))
    status.append(check_config(
        'client_private_key_path', 'Необходимо указать в конфиге путь до приватного ключа агента'))
    status.append(check_config(
        'debug_mode', 'Включен, а желательно выключить debug mode в конфиге для большей безопастности', 'Выключен', name='Debug mode выключен', is_warning=True))
    status.append(check_config(
        'opensearch_host', 'Необходимо указать в конфиге хост OpenSearch'))
    status.append(CheckStatus(name='Подключено к OpenSearch', status='fail' if opensearch_status['status'] != 'active' else 'success', detail=str(
        opensearch_status.get('detail', ''))))
    status.append(check_config(
        's3_url', 'Необходимо указать в конфиге ссылку на S3 хранилище (без протокола)'))
    status.append(CheckStatus(name='Подключено к S3', status='fail' if s3_status['status'] != 'active' else 'success', detail=str(
        s3_status.get('detail', ''))))

    return status
