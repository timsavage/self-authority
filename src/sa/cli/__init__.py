from getpass import getpass
from pathlib import Path
from typing import Optional

from pyapp.app import CliApplication, Arg

from sa import authority
from sa.consts import CA_DOMAIN
from sa.models import CreateCA, CreateDomain
from sa.storage import FileSystem

APP = CliApplication()


class Authority:
    group = APP.create_command_group("authority", aliases=("ca",))

    @staticmethod
    @group.command(name="init")
    async def init_authority(
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
        *,
        key_size: int = Arg(
            default=4096, help="Size of private key; defaults to 4096 bit"
        ),
    ):
        """Initialise a certificate authority."""
        ca = CreateCA(
            name=input("CA name:"),
            country_name=input("Country Name [AU]:") or "AU",
            state_or_province=input("State or Province [NSW]:") or "NSW",
            locality=input("Locality []:") or "",
            org_name=input("Org name []:") or "",
            org_unit_name=input("Org unit name []:") or "",
            email_address=input("Email address []:") or "",
        )
        passphrase = getpass("Pass-phrase:")

        storage = FileSystem(root)
        await authority.create_ca(ca, passphrase, storage, key_size=key_size)

    @staticmethod
    @group.command(name="root")
    async def export_root_certificate(
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        """Export the root certificate."""
        from cryptography.hazmat.primitives import serialization

        storage = FileSystem(root)
        certificate = await storage.read_certificate(CA_DOMAIN)
        print(certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"))


class Domains:
    group = APP.create_command_group(
        "domain", aliases=("d",), help_text="Actions for domains"
    )

    @staticmethod
    @group.command(aliases=("ls",))
    def list(
        query: Optional[str] = Arg(default="*"),
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        """List all managed certificates"""
        storage = FileSystem(root)
        domains = storage.list_domains(query)
        if domains:
            print("\n".join(f"- {name}" for name in domains))
        else:
            print("None!")

    @staticmethod
    @group.command(name="add", help_text="Add a domain")
    async def add_domain(
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        domain = CreateDomain(
            domain_name=input("Domain name:"),
            alt_names=None,
            country_name=input("Country Name [AU]:") or "AU",
            state_or_province=input("State or Province [NSW]:") or "NSW",
            locality=input("Locality []:") or "",
            org_name=input("Org name []:") or "",
            org_unit_name=input("Org unit name []:") or "",
            email_address=input("Email address []:") or "",
        )
        ca_passphrase = getpass("CA Passphrase:")

        storage = FileSystem(root)
        ca_certificate = await storage.read_certificate(CA_DOMAIN)
        ca_private_key = await storage.read_private_key(CA_DOMAIN, ca_passphrase)
        await authority.create_domain(domain, ca_certificate, ca_private_key, storage)

    @staticmethod
    @group.command(name="renew", help_text="Renew a domain")
    async def renew_domain(
        domain_name: str,
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        ca_passphrase = getpass("CA Passphrase:")

        storage = FileSystem(root)
        ca_certificate = await storage.read_certificate(CA_DOMAIN)
        ca_private_key = await storage.read_private_key(CA_DOMAIN, ca_passphrase)
        await authority.renew_domain(
            domain_name, ca_certificate, ca_private_key, storage
        )

    @staticmethod
    @group.command(name="export", help_text="Export certificate")
    async def export_domain(
        domain_name: str,
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        from cryptography.hazmat.primitives import serialization

        storage = FileSystem(root)
        certificate = await storage.read_certificate(domain_name)
        print(certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"))
