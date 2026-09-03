import os
from secrets import compare_digest

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import load_environment

API_KEY_HEADER_NAME = "X-API-Key"

api_key_header = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)

_cached_api_keys: list[str] | None = None


def reset_api_key_cache() -> None:
    global _cached_api_keys
    _cached_api_keys = None


def load_api_keys() -> list[str]:
    global _cached_api_keys
    if _cached_api_keys is None:
        load_environment()
        raw_value = os.getenv("PENGU1N_API_KEYS", "")
        _cached_api_keys = [
            api_key.strip()
            for api_key in raw_value.split(",")
            if api_key.strip()
        ]
    return _cached_api_keys


def is_valid_api_key(api_key: str) -> bool:
    for allowed_key in load_api_keys():
        if compare_digest(api_key, allowed_key):
            return True
    return False


def require_api_key(
    api_key: str | None = Security(api_key_header),
) -> None:
    if api_key is None or not is_valid_api_key(api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
