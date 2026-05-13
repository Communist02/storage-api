import json
import os
from typing import Any


config_path = os.path.expanduser('~/storage-api.json')

required_fields = [
    's3_url',
    'auth_api_url',
    'index_api_url',
    'access_key',
    'secret_key',
    'debug_mode',
    'opensearch_host',
    'opensearch_port',
    'opensearch_collections_index',
    'opensearch_files_index',
    'db_name',
    'db_user',
    'db_password',
    'opensearch_user',
    'opensearch_password'
]

default_config = {
    's3_url': 'localhost:9000',
    'auth_api_url': 'http://localhost:8081',
    'index_api_url': 'http://localhost:8010',
    'access_key': 'admin',
    'secret_key': 'password',
    'debug_mode': True,
    'opensearch_host': 'elastic-1.eco.dvo.ru',
    'opensearch_port': 9200,
    'opensearch_collections_index': 'collections',
    'opensearch_files_index': 'collections-files',
    'db_name': 'main',
    'db_user': 'root',
    'db_password': 'root',
    'opensearch_user': 'admin',
    'opensearch_password': 'OTFiZDkwMGRiOWQw1!'
}


class Config:
    def __init__(self, config_path=config_path):
        try:
            with open(config_path, 'r') as file:
                self.config = json.load(file)
                print(f"Config loaded from: {config_path}")
                self._validate_required_fields()
        except FileNotFoundError:
            print(f"Config file not found at {config_path}, created new file")
            with open(config_path, 'w') as file:
                file.write(json.dumps(default_config, indent=4))

            self.config = default_config
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in config file at {config_path}: {e}")
            self.config = default_config

    def _validate_required_fields(self):
        """Проверяет наличие всех обязательных полей"""
        missing_fields = []

        for field in required_fields:
            if field not in self.config or self.config.get(field) is None:
                missing_fields.append(field)

        if missing_fields:
            print(f"Missing required fields from config: {', '.join(missing_fields)}")

    def __getattr__(self, name: str) -> Any:
        return self.config.get(name)

    def get(self, key: str, default: Any = None) -> Any:
        return self.config.get(key, default)


config = Config()
