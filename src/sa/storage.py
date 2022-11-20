"""Storage of key/certificate materials."""
import abc
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sa.consts import (
    CA_DOMAIN_FOLDER,
    PRIVATE_KEY_FILE,
    TEXT_ENCODING,
    SIGNING_REQUEST_FILE,
    CERTIFICATE_FILE,
)


class Storage:
    """Generic storage of assets"""

    @abc.abstractmethod
    def list_domains(self, pattern: str = "*") -> list[str]:
        """List all certificates in storage."""

    @abc.abstractmethod
    def read_private_key(self, domain: str, passphrase: str) -> rsa.RSAPrivateKey:
        """Read private key from storage."""

    @abc.abstractmethod
    def write_private_key(
        self, key: rsa.RSAPrivateKey, domain: str, passphrase: str
    ) -> None:
        """Write private key to storage."""

    @abc.abstractmethod
    def read_csr(self, domain: str) -> x509.CertificateSigningRequest:
        """Read a CSR from storage."""

    @abc.abstractmethod
    def write_csr(self, csr: x509.CertificateSigningRequest, domain: str):
        """Write a CSR to storage."""

    @abc.abstractmethod
    def read_certificate(self, domain: str) -> x509.Certificate:
        """Read a certificate from storage."""

    @abc.abstractmethod
    def write_certificate(self, cert: x509.Certificate, domain: str):
        """Write a certificate to storage."""


class FileSystem(Storage):
    """Filesystem implementation of storage"""

    def __init__(self, root: Path, *, folder_mode: int = 0o700):
        """Initialise file-system storage."""
        self.root = root
        self.folder_mode = folder_mode

    def list_domains(self, pattern: str = "*") -> list[str]:
        """List all certificates in storage."""
        return [
            path.name
            for path in self.root.glob(pattern)
            if path.is_dir() and path.name != CA_DOMAIN_FOLDER
        ]

    def _file_path(self, domain: str, file_name: str):
        """Generate a file path within the storage location."""
        folder_path = self.root / domain
        folder_path.mkdir(mode=self.folder_mode, parents=True, exist_ok=True)
        return folder_path / file_name

    @staticmethod
    def _get_encryption(
        passphrase: str | None,
    ) -> serialization.KeySerializationEncryption:
        """Get appropriate encryption."""
        if passphrase:
            return serialization.BestAvailableEncryption(
                passphrase.encode(TEXT_ENCODING)
            )
        else:
            return serialization.NoEncryption()

    def write_private_key(
        self, key: rsa.RSAPrivateKey, domain: str, passphrase: str | None
    ) -> None:
        """Write private key to storage."""
        file_path = self._file_path(domain, PRIVATE_KEY_FILE)

        with file_path.open(mode="wb") as fp:
            fp.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.OpenSSH,
                    encryption_algorithm=self._get_encryption(passphrase),
                )
            )

    def read_private_key(self, domain: str, passphrase: str) -> rsa.RSAPrivateKey:
        """Read private key from storage."""
        file_path = self._file_path(domain, PRIVATE_KEY_FILE)
        with file_path.open(mode="rb") as fp:
            key = serialization.load_pem_private_key(
                fp.read(),
                passphrase.encode(TEXT_ENCODING) if passphrase else None,
            )
        if isinstance(key, rsa.RSAPrivateKey):
            return key
        raise TypeError(f"Key loaded is {type(key).__name__} expected an RSAPrivateKey")

    def read_csr(self, domain: str) -> x509.CertificateSigningRequest:
        """Read a CSR from storage."""
        file_path = self._file_path(domain, SIGNING_REQUEST_FILE)
        with file_path.open(mode="rb") as fp:
            return x509.load_pem_x509_csr(fp.read())

    def write_csr(self, csr: x509.CertificateSigningRequest, domain: str):
        """Write a CSR to storage."""
        file_path = self._file_path(domain, SIGNING_REQUEST_FILE)
        with file_path.open(mode="wb") as fp:
            fp.write(csr.public_bytes(serialization.Encoding.PEM))

    def read_certificate(self, domain: str) -> x509.Certificate:
        """Read a certificate from storage."""
        file_path = self._file_path(domain, CERTIFICATE_FILE)
        with file_path.open(mode="rb") as fp:
            return x509.load_pem_x509_certificate(fp.read())

    def write_certificate(self, cert: x509.Certificate, domain: str):
        """Write a certificate to storage."""
        file_path = self._file_path(domain, CERTIFICATE_FILE)
        with file_path.open(mode="wb") as fp:
            fp.write(cert.public_bytes(serialization.Encoding.PEM))
