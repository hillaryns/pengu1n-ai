import os

from app.core.security import reset_api_key_cache

TEST_API_KEY = "test-api-key-for-tests"
TEST_API_KEY_SECONDARY = "second-test-api-key-for-tests"


def configure_test_api_keys() -> None:
    os.environ["PENGU1N_API_KEYS"] = f"{TEST_API_KEY},{TEST_API_KEY_SECONDARY}"
    reset_api_key_cache()


def auth_headers(api_key: str = TEST_API_KEY) -> dict[str, str]:
    return {"X-API-Key": api_key}
