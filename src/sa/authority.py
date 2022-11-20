import logging
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sa.consts import (
    DEFAULT_CA_KEY_SIZE,
    CA_DOMAIN,
    DEFAULT_CA_VALID_RANGE,
    DEFAULT_DOMAIN_KEY_SIZE,
    DEFAULT_DOMAIN_VALID_RANGE,
)
from sa.models import CreateDomain, CreateCA
from sa.storage import Storage

_LOGGER = logging.getLogger(__package__)


def generate_private_key(key_size: int) -> rsa.RSAPrivateKey:
    """Generate an RSA private key pair."""
    return rsa.generate_private_key(65537, key_size=key_size)


def create_domain_csr(
    domain: CreateDomain,
    private_key: rsa.RSAPrivateKey,
) -> x509.CertificateSigningRequest:
    """Generate a signing request for a domain."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, domain.country_name),
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME, domain.state_or_province
            ),
            x509.NameAttribute(NameOID.LOCALITY_NAME, domain.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, domain.org_name),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, domain.org_unit_name),
            x509.NameAttribute(NameOID.COMMON_NAME, domain.domain_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, domain.email_address),
        ]
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject)
    if domain.alt_names:
        csr = csr.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in domain.alt_names]
            ),
            critical=False,
        )

    return csr.sign(private_key, algorithm=hashes.SHA256())


def generate_domain_certificate(
    csr: x509.CertificateSigningRequest,
    valid_from: datetime,
    valid_to: datetime,
    ca_certificate: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
) -> x509.Certificate:
    """Generate domain certificate.

    :param csr: Certificate signing request to be signed.
    :param valid_from: Date from which certificate is valid.
    :param valid_to: Date up to and including which the certificate is valid.
    :param ca_certificate: CA certificate to sign requested certificate with.
    :param ca_private_key: Private key of CA certificate.
    """

    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .sign(ca_private_key, hashes.SHA256())
    )


def generate_ca_certificate(
    ca: CreateCA,
    private_key: rsa.RSAPrivateKey,
    valid_from: datetime,
    valid_to: datetime,
) -> x509.Certificate:
    """Generate a CA Certificate.

    :param ca: Required fields for CA.
    :param private_key: Private key used to sign certificate.
    :param valid_from: Date from which certificate is valid.
    :param valid_to: Date up to and including which the certificate is valid.
    """
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, ca.country_name),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ca.state_or_province),
            x509.NameAttribute(NameOID.LOCALITY_NAME, ca.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca.org_name),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ca.org_unit_name),
            x509.NameAttribute(NameOID.COMMON_NAME, ca.name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, ca.email_address),
        ]
    )
    public_key = private_key.public_key()

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(x509.BasicConstraints(True, None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )


async def create_ca(
    ca: CreateCA,
    passphrase: str,
    storage: Storage,
    *,
    valid_for: timedelta = DEFAULT_CA_VALID_RANGE,
    key_size: int = DEFAULT_CA_KEY_SIZE,
) -> None:
    """Create a CA.

    :param ca: Required Certificate Authority parameters.
    :param passphrase: Passphrase required to encrypt private key.
    :param storage: Storage location for CA and files.
    :param valid_for: Time delta from now that the certificate is valid for.
    :param key_size: Key-size of private key; default 4096 bita.
    """
    now = datetime.utcnow()

    _LOGGER.info("Generating private key for %s", ca.name)
    private_key = generate_private_key(key_size)
    _LOGGER.info("Generating CA certificate for %s", ca.name)
    certificate = generate_ca_certificate(ca, private_key, now, now + valid_for)

    _LOGGER.info("Writing private key for %s", ca.name)
    await storage.write_private_key(private_key, CA_DOMAIN, passphrase)
    _LOGGER.info("Writing certificate for %s", ca.name)
    await storage.write_certificate(certificate, CA_DOMAIN)


async def create_domain(
    domain: CreateDomain,
    ca_certificate: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
    storage: Storage,
    *,
    valid_for: timedelta = DEFAULT_DOMAIN_VALID_RANGE,
    key_size: int = DEFAULT_DOMAIN_KEY_SIZE,
):
    """Create a domain request and sign."""
    now = datetime.utcnow()

    _LOGGER.info("Generating private key for %s", domain.domain_name)
    private_key = generate_private_key(key_size)
    _LOGGER.info("Writing private key for %s", domain.domain_name)
    await storage.write_private_key(private_key, domain.domain_name, None)

    _LOGGER.info("Create signing request for %s", domain.domain_name)
    csr = create_domain_csr(domain, private_key)
    _LOGGER.info("Writing CSR for %s", domain.domain_name)
    await storage.write_csr(csr, domain.domain_name)

    _LOGGER.info("Generate and sign certificate for %s", domain.domain_name)
    certificate = generate_domain_certificate(
        csr, now, now + valid_for, ca_certificate, ca_private_key
    )
    _LOGGER.info("Writing certificate for %s", domain.domain_name)
    await storage.write_certificate(certificate, domain.domain_name)


async def renew_domain(
    domain_name: str,
    ca_certificate: x509.Certificate,
    ca_private_key: rsa.RSAPrivateKey,
    storage: Storage,
    *,
    valid_for: timedelta = DEFAULT_DOMAIN_VALID_RANGE,
):
    """Regenerate and sign and existing certificate."""
    now = datetime.now()

    _LOGGER.info("Loading signing request for %s", domain_name)
    csr = await storage.read_csr(domain_name)
    _LOGGER.info("Generate and sign certificate for %s", domain_name)
    certificate = generate_domain_certificate(
        csr, now, now + valid_for, ca_certificate, ca_private_key
    )

    _LOGGER.info("Writing certificate for %s", domain_name)
    await storage.write_certificate(certificate, domain_name)
