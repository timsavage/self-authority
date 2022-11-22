import odin
from pyapp.conf import settings


class CreateCA(odin.AnnotatedResource):
    """All fields required to create a new CA"""

    name: str = odin.Options(
        error_messages={"required": "Name is required"},
        verbose_name="Name of CA",
    )
    country_name: str = odin.Options(
        default=lambda: settings.DEFAULT_COUNTRY_NAME,
        verbose_name="Country Name",
    )
    state_or_province: str = odin.Options(
        default=lambda: settings.DEFAULT_STATE_OR_PROVINCE,
        verbose_name="State or Province",
    )
    locality: str = odin.Options(
        empty=True,
        default="",
        verbose_name="Locality",
    )
    org_name: str = odin.Options(
        empty=True,
        default=lambda: settings.DEFAULT_ORG_NAME,
        verbose_name="Organisation Name",
    )
    org_unit_name: str = odin.Options(
        empty=True,
        default="",
        verbose_name="Organisation Unit Name",
    )
    email_address: odin.types.Email = odin.Options(
        empty=True,
        default=lambda: settings.DEFAULT_EMAIL,
        validators=[],
        verbose_name="Email Address",
    )

    def __str__(self):
        return self.name


class CreateDomain(odin.AnnotatedResource):
    """All fields required to create a new domain"""

    name: str = odin.Options(
        verbose_name="Name of Domain",
    )
    # alt_names: list[str] = odin.Options(
    #     verbose_name="Alternative Names",
    # )
    country_name: str = odin.Options(
        default=lambda: settings.DEFAULT_COUNTRY_NAME,
        verbose_name="Country Name",
    )
    state_or_province: str = odin.Options(
        default=lambda: settings.DEFAULT_STATE_OR_PROVINCE,
        verbose_name="State or Province",
    )
    locality: str = odin.Options(
        empty=True,
        default="",
        verbose_name="Locality",
    )
    org_name: str = odin.Options(
        empty=True,
        default=lambda: settings.DEFAULT_ORG_NAME,
        verbose_name="Organisation Name",
    )
    org_unit_name: str = odin.Options(
        empty=True,
        default="",
        verbose_name="Organisation Unit Name",
    )
    email_address: odin.types.Email = odin.Options(
        empty=True,
        default=lambda: settings.DEFAULT_EMAIL,
        validators=[],
        verbose_name="Email Address",
    )

    def __str__(self):
        return self.name
