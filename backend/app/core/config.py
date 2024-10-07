from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from pathlib import Path
from typing import List
import json
import os

# Load Media files
MEDIA_DIR = Path(__file__).resolve().parent.parent.parent / 'media'

# Load environment variables from .env file
env_path = Path(__file__).resolve().parent.parent.parent / '.env'
load_dotenv(dotenv_path=env_path)


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    DEBUG: bool
    ALLOWED_HOSTS: List[str]
    CORS_ORIGINS: List[str]
    ENVIRONMENT: str
    # Email settings
    EMAIL_HOST: str
    EMAIL_PORT: int
    EMAIL_USE_TLS: bool
    EMAIL_HOST_USER: str
    EMAIL_HOST_PASSWORD: str
    MAIN_FROM_NAME: str

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'

    @classmethod
    def parse_allowed_hosts(cls, value):
        if isinstance(value, str):
            return json.loads(value)
        return value

    @classmethod
    def parse_cors_origins(cls, value):
        if isinstance(value, str):
            return json.loads(value)
        return value


# Create an instance of Settings
settings = Settings()

# Convert ALLOWED_HOSTS to a list if it is a string
settings.ALLOWED_HOSTS = settings.parse_allowed_hosts(settings.ALLOWED_HOSTS)

# Convert CORS_ORIGINS to a list if it is a string
settings.CORS_ORIGINS = settings.parse_cors_origins(settings.CORS_ORIGINS)

# Debug print to check values
# print("ALLOWED_HOSTS:", settings.ALLOWED_HOSTS)
# print("CORS_ORIGINS:", settings.CORS_ORIGINS)
