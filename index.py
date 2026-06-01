import ssl
import httpx
from config import config
import base64
import truststore


async def create_index(collection_id: int, collection_name: str, encryption_key: bytes, jwt_token: str, path: str):
    encryption_key_str = base64.urlsafe_b64encode(encryption_key).decode()
    try:
        async with httpx.AsyncClient(verify=False if not config.debug_mode else truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)) as client:
            await client.post(
                f'{config.index_api_url}/indexing_collection',
                json={'collection_id': collection_id, 'collection_name': collection_name,
                      'encryption_key': encryption_key_str, 'jwt_token': jwt_token, 'path': path},
            )
    except httpx.TimeoutException as e:
        pass


async def indexing_files(collection_id: int, collection_name: str, encryption_key: bytes, jwt_token: str, files: list[str]):
    encryption_key_str = base64.urlsafe_b64encode(encryption_key).decode()
    try:
        async with httpx.AsyncClient(verify=False if not config.debug_mode else truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)) as client:
            await client.post(
                f'{config.index_api_url}/indexing_files',
                json={'collection_id': collection_id, 'collection_name': collection_name,
                      'encryption_key': encryption_key_str, 'jwt_token': jwt_token, 'files': files},
            )
    except httpx.TimeoutException as e:
        pass


async def delete_index(collection_id: int, collection_name: str, files: list[str]):
    try:
        async with httpx.AsyncClient(verify=False if not config.debug_mode else truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)) as client:
            await client.post(
                f'{config.index_api_url}/delete_files',
                json={'collection_id': collection_id,
                      'collection_name': collection_name, 'files': files},
            )
    except httpx.TimeoutException as e:
        pass
