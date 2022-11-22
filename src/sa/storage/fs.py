"""Filesystem implementation of Storage."""
import logging
from pathlib import Path

import arrow
from aiofile import async_open
from .base import BytesIOStorage
from ..consts import RESERVED_DOMAINS, CONFIG_FILE, CA_DOMAIN

_LOGGER = logging.getLogger(__package__)


def locate_repository_root(search_path: Path) -> Path | None:
    """Locate the root of the repository.

    Iterate up the parents of the supplied search path to find the first folder
    containing a ``.sa`` folder with required files inside.
    """
    search_path = search_path.absolute()
    while search_path:
        metadata_path = search_path / CA_DOMAIN
        if metadata_path.is_dir():
            if (metadata_path / CONFIG_FILE).is_file():
                return search_path
            _LOGGER.warning(
                "Found invalid repo domain %s; missing required config file", CA_DOMAIN
            )
            _LOGGER.debug("Missing config file %s", metadata_path / CONFIG_FILE)

        search_path = search_path.parent if len(search_path.parents) else None

    return None


class FileSystemStorage(BytesIOStorage):
    """Filesystem storage repository."""

    @classmethod
    def from_path(cls, search_path: Path) -> "FileSystemStorage":
        """Resolve file system path of repository."""
        if root_path := locate_repository_root(search_path):
            return cls(root_path)
        raise ValueError("No repository found")

    def __init__(self, root_path: Path, *, folder_mode: int = 0o700) -> None:
        self.root_path = root_path
        self.folder_mode = folder_mode

    async def has_domain(self, domain: str) -> bool:
        """The specified domain exists."""
        return (self.root_path / domain).is_dir()

    async def list_domains(self, pattern: str = "*") -> list[str]:
        """List all domains in storage."""
        return [
            path.name
            for path in self.root_path.glob(pattern)
            if path.is_dir() and path.name not in RESERVED_DOMAINS
        ]

    def _file_path(self, domain: str, file_name: str, *, parents: bool = True) -> Path:
        """Generate a file path within the storage location."""
        folder_path = self.root_path / domain
        if parents:
            folder_path.mkdir(mode=self.folder_mode, parents=True, exist_ok=True)
        return folder_path / file_name

    async def _read_bytes(self, domain: str, file_name: str) -> bytes:
        """Read bytes for storage layer"""
        file_path = self._file_path(domain, file_name, parents=False)
        async with async_open(file_path, mode="rb") as fp:
            return await fp.read()

    async def _write_bytes(
        self, domain: str, file_name: str, data: bytes, *, backup: bool = False
    ) -> int:
        """Write bytes to storage layer"""
        file_path = self._file_path(domain, file_name, parents=True)

        if backup and file_path.exists():
            backup_file_path = file_path.rename(
                file_path.parent / f"{file_path.name}.{arrow.utcnow().int_timestamp}"
            )
            _LOGGER.info("Backup file written to %s", backup_file_path.name)

        async with async_open(file_path, mode="wb") as fp:
            return await fp.write(data)
