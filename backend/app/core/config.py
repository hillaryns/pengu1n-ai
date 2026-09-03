from pathlib import Path

from dotenv import load_dotenv

_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
_ENV_FILE = _BACKEND_DIR / ".env"
_environment_loaded = False


def get_env_file_path() -> Path:
    return _ENV_FILE


def load_environment(*, force: bool = False) -> bool:
    """Load backend/.env into the process environment if present.

    Existing process environment variables are not overridden.
    Returns True when a .env file was found and loaded.
    """
    global _environment_loaded
    if _environment_loaded and not force:
        return False

    loaded = load_dotenv(dotenv_path=_ENV_FILE, override=False)
    _environment_loaded = True
    return bool(loaded)


def reset_environment_loader() -> None:
    global _environment_loaded
    _environment_loaded = False
