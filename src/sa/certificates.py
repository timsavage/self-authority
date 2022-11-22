import logging

import arrow
from arrow import Arrow
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from sa.models import CreateDomain, CreateCA

_LOGGER = logging.getLogger(__package__)


def domain_create_csr(
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
            x509.NameAttribute(NameOID.COMMON_NAME, domain.name),
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


def domain_generate_certificate(
    csr: x509.CertificateSigningRequest,
    valid_from: arrow.Arrow,
    valid_to: arrow.Arrow,
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
        .not_valid_before(valid_from.datetime)
        .not_valid_after(valid_to.datetime)
        .sign(ca_private_key, hashes.SHA256())
    )


def ca_generate_selfsigned_certificate(
    ca: CreateCA,
    private_key: rsa.RSAPrivateKey,
    valid_from: Arrow,
    valid_to: Arrow,
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
        .not_valid_before(valid_from.datetime)
        .not_valid_after(valid_to.datetime)
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
