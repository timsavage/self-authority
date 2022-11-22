import contextlib
import logging
from datetime import timedelta
from pathlib import Path

from arrow import Arrow
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from .certificates import (
    ca_generate_selfsigned_certificate,
    domain_create_csr,
    domain_generate_certificate,
)
from .consts import (
    CA_DEFAULT_KEY_SIZE,
    CA_DOMAIN,
    CA_DEFAULT_EXPIRY_DELTA,
    DOMAIN_DEFAULT_KEY_SIZE,
    DOMAIN_DEFAULT_EXPIRY_DELTA,
)
from .exceptions import RepositoryLocked
from .models import CreateCA, CreateDomain
from .storage import Storage, get_storage

# Type alias for passwords
Password = str

_LOGGER = logging.getLogger(__name__)


def generate_private_key(key_size: int) -> rsa.RSAPrivateKey:
    """Generate an RSA private key pair."""
    return rsa.generate_private_key(65537, key_size=key_size)


class RepositoryDomain:
    """Domain entry in a certificate repository."""

    @classmethod
    async def create(
        cls,
        domain: CreateDomain,
        expiry_delta: timedelta,
        repo: "CertificateRepository",
    ):
        """Create a domain."""
        now = Arrow.utcnow()
        storage = repo.storage

        _LOGGER.info("Generating private key for %r...", domain)
        private_key = generate_private_key(DOMAIN_DEFAULT_KEY_SIZE)
        _LOGGER.info("Writing private key...")
        await storage.write_private_key(domain.name, private_key, passphrase=None)

        _LOGGER.info("Create certificate signing request for %r", domain)
        csr = domain_create_csr(domain, private_key)
        _LOGGER.info("Writing CSR to %r...", domain)
        await storage.write_csr(domain.name, csr)

        _LOGGER.info("Creating and signing certificate with CA...")
        certificate = domain_generate_certificate(
            csr, now, now + expiry_delta, repo.ca_certificate, repo.ca_private_key
        )
        _LOGGER.info("Writing Certificate to %r...", domain)
        await storage.write_certificate(domain.name, certificate)

        # Create instance
        return cls(domain.name, certificate, repo)

    def __init__(
        self, domain: str, certificate: x509.Certificate, repo: "CertificateRepository"
    ):
        self.domain = domain
        self.repo = repo

        self._certificate = certificate

    @property
    def certificate(self) -> x509.Certificate:
        """Get the certificate (this is cached)"""
        return self._certificate

    @property
    def not_valid_before(self) -> Arrow:
        """Date before which certificate is not valid."""
        return Arrow.fromdatetime(self.certificate.not_valid_before)

    @property
    def not_valid_after(self) -> Arrow:
        """Date after which certificate is not valid."""
        return Arrow.fromdatetime(self.certificate.not_valid_after)

    @property
    def is_valid(self) -> bool:
        """Certificate is currently valid"""
        return self.not_valid_after >= Arrow.utcnow() >= self.not_valid_before

    def subject(self) -> dict[str, str]:
        """Get subject values"""

        return {self.certificate.subject}
        print(self.certificate.subject)

    async def renew(
        self,
        *,
        backup: bool = True,
        expiry_delta: timedelta = DOMAIN_DEFAULT_EXPIRY_DELTA,
    ):
        """Renew an existing certificate."""

        now = Arrow.utcnow()
        storage = self.repo.storage

        _LOGGER.info("Load existing CSR for %r...", self.domain)
        csr = await storage.read_csr(self.domain)

        _LOGGER.info("Regenerate and sign certificate for %r", self.domain)
        self._certificate = certificate = domain_generate_certificate(
            csr,
            now,
            now + expiry_delta,
            self.repo.ca_certificate,
            self.repo.ca_private_key,
        )

        _LOGGER.info("Writing certificate for %s", self.domain)
        await storage.write_certificate(self.domain, certificate, backup=backup)

    def __str__(self):
        if self.is_valid:
            self.subject()
            return f"Valid, expires {self.not_valid_after.humanize()}"
        else:
            return "Not Valid"


class CertificateRepository:
    """Certificate Repository"""

    @classmethod
    async def create_selfsigned(
        cls,
        ca: CreateCA,
        ca_passphrase: Password,
        storage: Storage,
        exist_ok: bool = False,
        expiry_delta: timedelta = CA_DEFAULT_EXPIRY_DELTA,
        key_size: int = CA_DEFAULT_KEY_SIZE,
    ):
        """Create a repository."""
        if exist_ok is False and await storage.has_domain(CA_DOMAIN):
            raise ValueError("CA already exists.")

        _LOGGER.debug("Writing repository config...")
        await storage.write_config(CA_DOMAIN, {})

        _LOGGER.info("Generating private key for CA...")
        private_key = generate_private_key(key_size)
        _LOGGER.info("Writing private key for %s", ca.name)
        await storage.write_private_key(
            CA_DOMAIN, private_key, passphrase=ca_passphrase
        )

        now = Arrow.utcnow()
        _LOGGER.info("Creating and signing CA certificate...")
        certificate = ca_generate_selfsigned_certificate(
            ca, private_key, now, now + expiry_delta
        )
        _LOGGER.info("Writing certificate for %s", ca.name)
        await storage.write_certificate(CA_DOMAIN, certificate)

        return cls(certificate, storage)

    @classmethod
    async def from_url(cls, url: str | Path):
        """Create repository from a URL."""
        storage = get_storage(url)
        ca_certificate = await storage.read_certificate(CA_DOMAIN)
        return cls(ca_certificate, storage)

    def __init__(self, ca_certificate: x509.Certificate, storage: Storage):
        self.storage = storage

        self._ca_certificate = ca_certificate
        self._ca_private_key: rsa.RSAPrivateKey | None = None

    @property
    def ca_certificate(self) -> x509.Certificate:
        """Get the CA certificate (this is cached)"""
        return self._ca_certificate

    @property
    def ca_private_key(self) -> rsa.RSAPrivateKey:
        """Get CA private key (unlock required)"""
        if self._ca_private_key is None:
            raise RepositoryLocked
        return self._ca_private_key

    @contextlib.asynccontextmanager
    async def unlock(self, passphrase: Password) -> "RepositoryDomain":
        """Unlock for operations that require private key."""
        self._ca_certificate = await self.storage.read_certificate(CA_DOMAIN)
        self._ca_private_key = await self.storage.read_private_key(
            CA_DOMAIN, passphrase=passphrase
        )
        yield self
        self._ca_private_key = None

    async def list_domains(self, pattern: str = "*") -> list[str]:
        """List all available domains."""
        return await self.storage.list_domains(pattern)

    async def create_domain(
        self,
        domain: CreateDomain,
        *,
        exist_ok: bool = False,
        expiry_delta: timedelta = DOMAIN_DEFAULT_EXPIRY_DELTA,
    ) -> RepositoryDomain:
        """Create a domain entry."""
        if exist_ok is False and await self.storage.has_domain(domain.name):
            raise ValueError(f"Domain {domain!r} already exists.")

        return await RepositoryDomain.create(domain, expiry_delta, self)

    async def get_domain(self, domain: str) -> RepositoryDomain | None:
        """Get a domain"""
        certificate = await self.storage.read_certificate(domain)
        return RepositoryDomain(domain, certificate, self)
