# ============================================
# File    : config.py
# Purpose : Central configuration for the app
#           Loads settings from .env file
# ============================================

from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    """
    All app settings loaded from .env file.
    pydantic_settings validates types automatically.
    If DATABASE_URL is missing it raises an error
    immediately — fail fast, fail loud.
    """
    database_url: str
    secret_key: str
    api_version: str = "v1"
    debug: bool = True
    groq_api_key: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

@lru_cache()
def get_settings() -> Settings:
    """
    Returns cached settings instance.
    lru_cache means this function only reads
    the .env file once — not on every request.
    """
    return Settings()
