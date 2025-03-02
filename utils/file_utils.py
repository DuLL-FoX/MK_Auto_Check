import logging
import os


def ensure_directory_exists(directory_path: str) -> None:
    if not directory_path or directory_path == '.':
        return

    try:
        os.makedirs(directory_path, exist_ok=True)
        logging.debug(f"Directory '{directory_path}' ensured.")
    except Exception as e:
        logging.error(f"Failed to create directory '{directory_path}': {e}")
        raise