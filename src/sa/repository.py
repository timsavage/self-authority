import logging
from datetime import timedelta

import arrow
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
from .models import CreateCA, CreateDomain
from .storage import Storage

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
        ca_passphrase: Password,
        repo: "CertificateRepository",
    ):
        """Create a domain."""
        now = arrow.utcnow()
        storage = repo.storage
        ca_certificate = await repo.ca_certificate()
        ca_private_key = await storage.read_private_key(
            CA_DOMAIN, passphrase=ca_passphrase
        )

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
            csr, now, now + expiry_delta, ca_certificate, ca_private_key
        )
        _LOGGER.info("Writing Certificate to %r...", domain)
        await storage.write_certificate(domain.name, certificate)

        # Create instance
        instance = cls(domain.name, repo)
        instance._certificate = certificate
        return instance

    def __init__(self, domain: str, repo: "CertificateRepository"):
        self.domain = domain
        self.repo = repo

        self._certificate: x509.Certificate | None = None

    async def certificate(self) -> x509.Certificate:
        """Get the CA certificate (this is cached)"""
        if self._certificate is None:
            self._certificate = await self.repo.storage.read_certificate(CA_DOMAIN)
        return self._certificate

    async def renew(
        self,
        ca_passphrase: Password,
        *,
        backup: bool = True,
        expiry_delta: timedelta = CA_DEFAULT_EXPIRY_DELTA,
    ):
        """Renew an existing certificate."""

        now = arrow.utcnow()
        storage = self.repo.storage
        ca_certificate = await self.repo.ca_certificate()
        ca_private_key = await self.repo.ca_private_key(ca_passphrase)

        _LOGGER.info("Load existing CSR for %r...", self.domain)
        csr = await storage.read_csr(self.domain)

        _LOGGER.info("Regenerate and sign certificate for %r", self.domain)
        certificate = domain_generate_certificate(
            csr, now, now + expiry_delta, ca_certificate, ca_private_key
        )

        _LOGGER.info("Writing certificate for %s", self.domain)
        await storage.write_certificate(self.domain, certificate, backup=backup)


class CertificateRepository:
    """Certificate Repository"""

    def __init__(self, storage: Storage):
        self.storage = storage

        self._ca_cert: x509.Certificate | None = None

    async def create_selfsigned(
        self,
        ca: CreateCA,
        passphrase: str,
        *,
        exist_ok: bool = False,
        expiry_delta: timedelta = CA_DEFAULT_EXPIRY_DELTA,
    ):
        """Create a self-signed CA certificate."""
        if exist_ok is False and await self.storage.has_domain(CA_DOMAIN):
            raise ValueError("CA already exists.")

        now = arrow.utcnow()
        storage = self.storage

        _LOGGER.info("Generating private key for CA...")
        private_key = generate_private_key(CA_DEFAULT_KEY_SIZE)
        _LOGGER.info("Writing private key for %s", ca.name)
        await storage.write_private_key(CA_DOMAIN, private_key, passphrase=passphrase)

        _LOGGER.info("Creating and signing CA certificate...")
        certificate = ca_generate_selfsigned_certificate(
            ca, private_key, now, now + expiry_delta
        )
        _LOGGER.info("Writing certificate for %s", ca.name)
        await storage.write_certificate(CA_DOMAIN, certificate)

    async def ca_certificate(self) -> x509.Certificate:
        """Get the CA certificate (this is cached)"""
        if self._ca_cert is None:
            _LOGGER.info("Loading CA certificate...")
            self._ca_cert = await self.storage.read_certificate(CA_DOMAIN)
        return self._ca_cert

    async def ca_private_key(self, passphrase: str) -> rsa.RSAPrivateKey:
        """Get the CA private key (this IS NOT and MUST NOT be cached)."""
        return await self.storage.read_private_key(CA_DOMAIN, passphrase=passphrase)

    async def domain_list(self, pattern: str = "*") -> list[str]:
        """List all available domains."""
        return await self.storage.list_domains(pattern)

    async def domain_create(
        self,
        domain: CreateDomain,
        ca_passphrase: Password,
        *,
        exist_ok: bool = False,
        expiry_delta: timedelta = DOMAIN_DEFAULT_EXPIRY_DELTA,
    ) -> RepositoryDomain:
        """Create a domain entry."""
        if exist_ok is False and await self.storage.has_domain(domain.name):
            raise ValueError(f"Domain {domain!r} already exists.")

        return await RepositoryDomain.create(domain, expiry_delta, ca_passphrase, self)

    async def domain_get(self, domain: str) -> RepositoryDomain | None:
        """Get a domain"""
        if await self.storage.has_domain(domain):
            return RepositoryDomain(domain, self)
        return None
