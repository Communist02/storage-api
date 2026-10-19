import json
import os
from typing import Any
from checklist import BaseModel


config_path = os.path.expanduser('~/storage-api.json')


class Config(BaseModel):
    s3_url: str = 'localhost:9000'
    auth_api_url: str = 'http://localhost:8080'
    index_api_url: str = 'http://localhost:8010'
    s3_access_key: str = 'admin'
    s3_secret_key: str = 'password'
    debug_mode: bool = True
    db_host: str = 'db.eco.example.ru'
    db_name: str = 'main'
    db_user: str = 'root'
    db_password: str = 'root'
    opensearch_host: str = 'elastic-1.eco.example.ru'
    opensearch_port: int = 9200
    opensearch_collections_index: str = 'collections'
    opensearch_files_index: str = 'collections-files'
    opensearch_user: str = 'admin'
    opensearch_password: str = 'OTFiZDkwMGRiOWQw1!'
    client_cert_path: str = ''
    client_private_key_path: str = ''


class ConfigManager(Config):
    """
    Наследник Config, который умеет загружать/сохранять себя из JSON.
    Все поля доступны напрямую: config.issuer, config.db_host и т.д.
    """

    def __init__(self, config_path: str | None = config_path, **data: Any) -> None:
        if config_path is None:
            super().__init__(**data)
            return

        loaded: dict[str, Any] | None = None
        try:
            with open(config_path, 'r') as file:
                loaded = json.load(file)
            print(f"Config loaded from: {config_path}")
        except FileNotFoundError:
            print(f"Config file not found at {config_path}, created new file")
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in config file at {config_path}: {e}")

        if loaded is None:
            super().__init__(**data)
            self._save_config(config_path)
            return

        # Дополняем недостающие поля значениями по умолчанию
        defaults = Config().model_dump()
        missing = [k for k, v in defaults.items(
        ) if k not in loaded or loaded[k] is None]
        if missing:
            print(f"Missing required fields from config: {', '.join(missing)}")
            print("Added missing fields with default values")
            for k in missing:
                loaded[k] = defaults[k]

        super().__init__(**loaded)

        if missing:
            self._save_config(config_path)

    def _save_config(self, config_path: str) -> None:
        try:
            with open(config_path, 'w') as file:
                file.write(self.model_dump_json(indent=4))
            print(f"Config file updated at: {config_path}")
        except Exception as e:
            print(f"Warning: Could not save config to file: {e}")

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


config = ConfigManager()
default_config = ConfigManager(None)
