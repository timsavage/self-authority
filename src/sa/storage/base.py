"""ABC for storage services."""
import abc
from typing import Mapping

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    Encoding,
    PrivateFormat,
    load_pem_private_key,
)

from sa.consts import (
    PRIVATE_KEY_FILE,
    TEXT_ENCODING,
    SIGNING_REQUEST_FILE,
    CERTIFICATE_FILE,
)


class Storage:
    """Generic storage of assets"""

    @abc.abstractmethod
    async def list_domains(
        self,
        pattern: str = "*",
    ) -> list[str]:
        """List all domains in storage.

        :param pattern: Glob pattern to filter list by; default is * (all)
        """

    @abc.abstractmethod
    async def has_domain(
        self,
        domain: str,
    ) -> bool:
        """The specified domain exists.

        :param domain: Domain to check.
        """

    @abc.abstractmethod
    async def read_config(self, domain: str) -> Mapping[str, ...]:
        """Read configuration from storage.

        :param domain: Domain to read config from.
        """

    @abc.abstractmethod
    async def write_config(self, domain: str, config: Mapping[str, ...]) -> None:
        """Write configuration to storage.

        :param domain: Domain to write config to.
        :param config: Configuration key/value pairs.
        """

    @abc.abstractmethod
    async def read_private_key(
        self,
        domain: str,
        *,
        passphrase: str | None,
    ) -> rsa.RSAPrivateKey:
        """Read private key from storage.

        :param domain: Domain to read key from.
        :param passphrase: Optional passphrase to dencrypt an encrypted private key.
        """

    @abc.abstractmethod
    async def write_private_key(
        self,
        domain: str,
        key: rsa.RSAPrivateKey,
        *,
        passphrase: str | None,
    ) -> None:
        """Write private key to storage.

        :param domain: Domain to write key to.
        :param key: Private key to write.
        :param passphrase: Optional passphrase to encrypt private key.
        """

    @abc.abstractmethod
    async def read_csr(
        self,
        domain: str,
    ) -> x509.CertificateSigningRequest:
        """Read a CSR from storage.

        :param domain: Domain to read CSR from.
        """

    @abc.abstractmethod
    async def write_csr(
        self,
        domain: str,
        csr: x509.CertificateSigningRequest,
    ):
        """Write a CSR to storage.

        :param domain: Domain to write CSR to.
        :param csr: CSR to write.
        """

    @abc.abstractmethod
    async def read_certificate(
        self,
        domain: str,
    ) -> x509.Certificate:
        """Read a certificate from storage.

        :param domain: Domain to read certificate from.
        """

    @abc.abstractmethod
    async def write_certificate(
        self,
        domain: str,
        cert: x509.Certificate,
    ):
        """Write a certificate to storage.

        :param domain: Domain to write certificate to.
        :param cert: Certificate to write.
        """


class BytesIOStorage(Storage):
    """Generic bytes IO style storage."""

    @abc.abstractmethod
    async def _read_bytes(self, domain: str, file_name: str) -> bytes:
        """Read bytes for storage layer"""

    @abc.abstractmethod
    async def _write_bytes(self, domain: str, file_name: str, data: bytes) -> int:
        """Write bytes to storage layer"""

    async def read_config(self, domain: str) -> Mapping[str, ...]:
        """Read configuration from storage.

        :param domain: Domain to read config from.
        """

    async def write_config(self, domain: str, config: Mapping[str, ...]) -> None:
        """Write configuration to storage.

        :param domain: Domain to write config to.
        :param config: Configuration key/value pairs.
        """

    async def read_private_key(
        self,
        domain: str,
        *,
        passphrase: str | None,
    ) -> rsa.RSAPrivateKey:
        """Read private key from storage.

        :param domain: Domain to read key from.
        :param passphrase: Optional passphrase to dencrypt an encrypted private key.
        """
        data = await self._read_bytes(domain, PRIVATE_KEY_FILE)
        key = load_pem_private_key(
            data,
            passphrase.encode(TEXT_ENCODING) if passphrase else None,
        )
        if isinstance(key, rsa.RSAPrivateKey):
            return key
        raise TypeError(f"Key loaded is {type(key).__name__} expected an RSAPrivateKey")

    async def write_private_key(
        self,
        domain: str,
        key: rsa.RSAPrivateKey,
        *,
        passphrase: str | None,
    ) -> None:
        """Write private key to storage.

        :param domain: Domain to write key to.
        :param key: Private key to write.
        :param passphrase: Optional passphrase to encrypt private key.
        """
        encryption = (
            BestAvailableEncryption(passphrase.encode(TEXT_ENCODING))
            if passphrase
            else NoEncryption()
        )
        await self._write_bytes(
            domain,
            PRIVATE_KEY_FILE,
            key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption,
            ),
        )

    async def read_csr(
        self,
        domain: str,
    ) -> x509.CertificateSigningRequest:
        """Read a CSR from storage.

        :param domain: Domain to read CSR from.
        """
        return x509.load_pem_x509_csr(
            await self._read_bytes(domain, SIGNING_REQUEST_FILE)
        )

    async def write_csr(
        self,
        domain: str,
        csr: x509.CertificateSigningRequest,
    ):
        """Write a CSR to storage.

        :param domain: Domain to write CSR to.
        :param csr: CSR to write.
        """
        await self._write_bytes(
            domain, SIGNING_REQUEST_FILE, csr.public_bytes(Encoding.PEM)
        )

    async def read_certificate(
        self,
        domain: str,
    ) -> x509.Certificate:
        """Read a certificate from storage.

        :param domain: Domain to read certificate from.
        """
        return x509.load_pem_x509_certificate(
            await self._read_bytes(domain, CERTIFICATE_FILE)
        )

    async def write_certificate(
        self,
        domain: str,
        cert: x509.Certificate,
    ):
        """Write a certificate to storage.

        :param domain: Domain to write certificate to.
        :param cert: Certificate to write.
        """
        await self._write_bytes(
            domain, CERTIFICATE_FILE, cert.public_bytes(Encoding.PEM)
        )
