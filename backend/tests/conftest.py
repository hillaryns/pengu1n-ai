import pytest

from tests.auth_helpers import configure_test_api_keys


@pytest.fixture(autouse=True)
def _configure_api_keys_for_tests():
    configure_test_api_keys()
    yield
