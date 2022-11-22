"""Storage of key/certificate materials."""
from pathlib import Path

from .base import Storage
from .fs import FileSystemStorage

__all__ = ("get_storage", "Storage", "FileSystemStorage")


def get_storage(url: str | Path) -> Storage:
    """Get a supported storage instance."""
    if isinstance(url, Path):
        return FileSystemStorage.from_path(url)
    raise ValueError("Unable to determine storage.")
