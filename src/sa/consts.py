"""Self Authority constants."""
from datetime import timedelta
from typing import Final, Sequence

TEXT_ENCODING: Final[str] = "UTF8"
"""Text encoding used for all string operations."""

CA_DOMAIN: Final[str] = ".ca"
"""Domain for the CA."""

CA_DEFAULT_KEY_SIZE: Final[int] = 4096
"""Default size of private key used by CA."""

CA_DEFAULT_EXPIRY_DELTA: Final[timedelta] = timedelta(days=365 * 10)
"""Default timedelta a CA certificate is valid for."""

DOMAIN_DEFAULT_KEY_SIZE: Final[int] = 2048
"""Default size of private key used for managed domains; default 10 years"""

DOMAIN_DEFAULT_EXPIRY_DELTA: Final[timedelta] = timedelta(days=365)
"""Default timedelta a signed certificate is valid for; default 1 year"""

CONFIG_FILE: Final[str] = "config.json"
PRIVATE_KEY_FILE: Final[str] = "private.key.pem"
SIGNING_REQUEST_FILE: Final[str] = "signing-request.csr.pem"
SIGNING_EXTENSION_FILE: Final[str] = "signing-request.ext"
CERTIFICATE_FILE: Final[str] = "certificate.crt.pem"

RESERVED_DOMAINS: Final[Sequence[str]] = (CA_DOMAIN, ".git")
"""Reserved domain names."""
