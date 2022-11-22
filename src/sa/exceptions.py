class SelfAuthorityError(Exception):
    pass


class CertificateRepositoryError(Exception):
    pass


class RepositoryLocked(CertificateRepositoryError):
    """Repository private key is not available."""
