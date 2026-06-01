from opensearchpy import NotFoundError, AsyncOpenSearch
from config import config

# auth = ('admin', os.getenv('OPENSEARCH_PASS'))
# For testing only. Don't store credentials in code.
auth = (config.opensearch_user, config.opensearch_password)


class OpenSearchManager:
    def __init__(self, host: str = config.opensearch_host, port: int = config.opensearch_port, auth: tuple = auth):
        self.host = host
        self.port = port
        self.auth = auth
        

    # Не работает
    async def create_index(self, index_name: str = config.opensearch_collections_index):
        async with AsyncOpenSearch(
            hosts=[{'host': self.host, 'port': self.port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=True,
            verify_certs=not config.debug_mode,
            ssl_assert_hostname=not config.debug_mode,
            ssl_show_warn=not config.debug_mode,
        ) as client:
            response = await client.indices.create(
                index=index_name)

    async def update_document(self, doc_id: int, document: dict, index_name: str = config.opensearch_collections_index):
        async with AsyncOpenSearch(
            hosts=[{'host': self.host, 'port': self.port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=True,
            verify_certs=not config.debug_mode,
            ssl_assert_hostname=not config.debug_mode,
            ssl_show_warn=not config.debug_mode,
        ) as client:
            response = await client.index(
                index=index_name,
                body=document,
                id=doc_id,
                refresh=True,
            )

    async def delete_document(self, doc_id: int, index_name: str = config.opensearch_collections_index):
        async with AsyncOpenSearch(
            hosts=[{'host': self.host, 'port': self.port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=True,
            verify_certs=not config.debug_mode,
            ssl_assert_hostname=not config.debug_mode,
            ssl_show_warn=not config.debug_mode,
        ) as client:
            response = await client.delete(
                index=index_name,
                id=doc_id,
            )

    async def create_policy_to_user(self, role_name: str, role_content: dict):
        async with AsyncOpenSearch(
            hosts=[{'host': self.host, 'port': self.port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=True,
            verify_certs=not config.debug_mode,
            ssl_assert_hostname=not config.debug_mode,
            ssl_show_warn=not config.debug_mode,
        ) as client:
            response = await client.security.create_role(
                role=role_name,
                body=role_content
            )
            response = await client.security.create_role_mapping(
                role=role_name,
                body={'backend_roles': [role_name]}
            )

    async def get_document(self, doc_id: int | str, index_name: str = config.opensearch_collections_index) -> dict | None:
        async with AsyncOpenSearch(
            hosts=[{'host': self.host, 'port': self.port}],
            http_compress=True,
            http_auth=auth,
            use_ssl=True,
            verify_certs=not config.debug_mode,
            ssl_assert_hostname=not config.debug_mode,
            ssl_show_warn=not config.debug_mode,
        ) as client:
            try:
                response = await client.get(
                    index=index_name,
                    id=doc_id,
                )
                return response['_source']
            except NotFoundError:
                return None

    async def search_collections(self, text: str, jwt_token: str, index_collections: str = config.opensearch_collections_index, index_files: str = config.opensearch_files_index):
        size_collections = 100
        size_files = 1000

        auth_header = {'Authorization': f'Bearer {jwt_token}'}
        query_collections = {
            'size': size_collections,
            'query': {
                'multi_match': {
                    'query': text,
                    'fields': ['*'],  # Искать по всем полям
                    'type': 'best_fields',  # Лучшее совпадение по одному полю
                    'fuzziness': 'AUTO',  # Автоматическая нечеткость для опечаток
                    'operator': 'or',
                    'analyzer': 'russian'
                }
            },
            'highlight': {  # Подсветка результатов
                'fields': {
                    '*': {}  # Подсветка во всех полях
                }
            }
        }
        query_files = {
            'size': size_files,
            'query': {
                'bool': {
                    'should': [
                        # 1. Точное совпадение имени
                        {
                            'match_phrase': {
                                'name': {
                                    'query': text,
                                    'boost': 3.0
                                }
                            }
                        },

                        # 2. Нечеткий поиск по name
                        {
                            'match': {
                                'name': {
                                    'query': text,
                                    'fuzziness': 'AUTO',
                                    'boost': 2.0
                                }
                            }
                        },

                        # 3. Нечеткий поиск по other_text (всё содержимое JSON)
                        {
                            'match': {
                                'other_text': {
                                    'query': text,
                                    'fuzziness': 'AUTO',
                                    'analyzer': 'english'
                                }
                            }
                        },

                        # 4. Точное совпадение фразы в other_text
                        {
                            'match_phrase': {
                                'other_text': {
                                    'query': text,
                                    'boost': 1.5
                                }
                            }
                        },

                        # 5. Поиск по подстроке (но осторожно — wildcard дорогой)
                        {
                            'wildcard': {
                                'name': f'*{text.lower()}*'
                            }
                        },

                        # 6. Поиск по подстроке внутри other_text
                        {
                            'wildcard': {
                                'other_text': f'*{text.lower()}*'
                            }
                        }
                    ]
                }
            },

            # Подсветка найденного текста
            'highlight': {
                'fields': {
                    'name': {},
                    'path': {},
                    'format': {},
                    'other_text': {}
                }
            }
        }
        async with AsyncOpenSearch(
            hosts=[{'host': config.opensearch_host,
                    'port': config.opensearch_port}],
            http_compress=True,
            headers=auth_header,
            use_ssl=True,
            verify_certs=not config.debug_mode,
            ssl_assert_hostname=not config.debug_mode,
            ssl_show_warn=not config.debug_mode
        ) as client:
            response = await client.search(
                body=query_collections,
                index=index_collections,
            )
            collections = response['hits']['hits']
            response = await client.search(
                body=query_files,
                index=index_files,
            )
            files = response['hits']['hits']
        return {'collections': collections, 'files': files}
