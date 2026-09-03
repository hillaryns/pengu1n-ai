import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.core.config import (
    get_env_file_path,
    load_environment,
    reset_environment_loader,
)
from app.core.security import is_valid_api_key, load_api_keys, reset_api_key_cache


class EnvConfigTests(unittest.TestCase):
    def setUp(self):
        self._previous_api_keys = os.environ.pop("PENGU1N_API_KEYS", None)
        reset_api_key_cache()
        reset_environment_loader()

    def tearDown(self):
        reset_api_key_cache()
        reset_environment_loader()
        if self._previous_api_keys is None:
            os.environ.pop("PENGU1N_API_KEYS", None)
        else:
            os.environ["PENGU1N_API_KEYS"] = self._previous_api_keys

    def test_env_file_path_points_at_backend_dotenv(self):
        env_path = get_env_file_path()
        self.assertEqual(env_path.name, ".env")
        self.assertTrue(env_path.parent.name == "backend")

    def test_load_api_keys_from_dotenv_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text(
                "PENGU1N_API_KEYS=dotenv-test-key-one, dotenv-test-key-two\n",
                encoding="utf-8",
            )

            with patch("app.core.config._ENV_FILE", env_path):
                reset_environment_loader()
                loaded = load_environment(force=True)
                reset_api_key_cache()
                keys = load_api_keys()

            self.assertTrue(loaded)
            self.assertEqual(len(keys), 2)
            self.assertTrue(is_valid_api_key("dotenv-test-key-one"))
            self.assertTrue(is_valid_api_key("dotenv-test-key-two"))
            self.assertFalse(is_valid_api_key("not-a-configured-key"))

    def test_process_environment_overrides_dotenv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text(
                "PENGU1N_API_KEYS=from-dotenv-file-only\n",
                encoding="utf-8",
            )
            os.environ["PENGU1N_API_KEYS"] = "from-process-env"

            with patch("app.core.config._ENV_FILE", env_path):
                reset_environment_loader()
                load_environment(force=True)
                reset_api_key_cache()
                keys = load_api_keys()

            self.assertEqual(keys, ["from-process-env"])
            self.assertTrue(is_valid_api_key("from-process-env"))
            self.assertFalse(is_valid_api_key("from-dotenv-file-only"))

    def test_missing_dotenv_file_is_safe(self):
        missing_path = Path(tempfile.gettempdir()) / "pengu1n-missing-env-file.env"
        if missing_path.exists():
            missing_path.unlink()

        with patch("app.core.config._ENV_FILE", missing_path):
            reset_environment_loader()
            loaded = load_environment(force=True)
            reset_api_key_cache()
            keys = load_api_keys()

        self.assertFalse(loaded)
        self.assertEqual(keys, [])


if __name__ == "__main__":
    unittest.main()
