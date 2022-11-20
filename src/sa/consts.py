from datetime import timedelta
from typing import Final

TEXT_ENCODING: Final[str] = "UTF8"
"""Text encoding used for all string operations."""

DEFAULT_CA_KEY_SIZE: Final[int] = 4096
"""Default size of private key used by CA."""

DEFAULT_CA_VALID_RANGE: Final[timedelta] = timedelta(days=365 * 10)
"""Default timedelta a CA certificate is valid for."""

DEFAULT_DOMAIN_KEY_SIZE: Final[int] = 2048
"""Default size of private key used for managed domains; default 10 years"""

DEFAULT_DOMAIN_VALID_RANGE: Final[timedelta] = timedelta(days=365)
"""Default timedelta a signed certificate is valid for; default 1 year"""

CA_CONFIG_FILE: Final[str] = ".ca-config.toml"
"""Config file for the CA."""

CA_DOMAIN_FOLDER: Final[str] = ".ca"
PRIVATE_KEY_FILE: Final[str] = "private.key.pem"
SIGNING_REQUEST_FILE: Final[str] = "signing-request.csr.pem"
SIGNING_EXTENSION_FILE: Final[str] = "signing-request.ext"
CERTIFICATE_FILE: Final[str] = "certificate.crt.pem"
