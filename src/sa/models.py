from typing import NamedTuple


class CreateCA(NamedTuple):
    """All fields required to create a new CA"""

    name: str
    country_name: str
    state_or_province: str
    locality: str
    org_name: str
    org_unit_name: str
    email_address: str


class CreateDomain(NamedTuple):
    """All fields required to create a new domain"""

    domain_name: str
    alt_names: list[str] | None
    country_name: str
    state_or_province: str
    locality: str
    org_name: str
    org_unit_name: str
    email_address: str
