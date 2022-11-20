from typing import Final

TEXT_ENCODING: Final[str] = "UTF8"
"""Text encoding used for all string operations."""

DEFAULT_CA_KEY_SIZE: Final[int] = 4096
"""Default size of private key used by CA."""

DEFAULT_DOMAIN_KEY_SIZE: Final[int] = 2048
"""Default size of private key used for managed domains."""

CA_CONFIG_FILE: Final[str] = ".ca-config.toml"
"""Config file for the CA."""

CA_DOMAIN_FOLDER: Final[str] = ".ca"

PRIVATE_KEY_FILE: Final[str] = "private.key.pem"
SIGNING_REQUEST_FILE: Final[str] = "signing-request.csr.pem"
SIGNING_EXTENSION_FILE: Final[str] = "signing-request.ext"
CERTIFICATE_FILE: Final[str] = "certificate.crt.pem"
