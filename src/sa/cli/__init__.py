from getpass import getpass
from pathlib import Path
from typing import Optional

from pyapp.app import CliApplication, Arg
from rich import print
from rich.prompt import Prompt

from .resource_input import ResourceInput
from ..models import CreateCA, CreateDomain
from ..storage import FileSystemStorage
from ..repository import CertificateRepository

APP = CliApplication(description="Your Personal Certificate Authority")
main = APP.dispatch


class Authority:
    group = APP.create_command_group(
        "authority",
        aliases=("ca",),
        help_text="Authority commands",
    )

    @staticmethod
    @group.command(name="init")
    async def init_authority(
        root: Optional[Path] = Arg(
            default=Path("."),
            help="Root path of authority storage",
        ),
        *,
        force: bool = Arg(
            default=False,
            help="Overwrite any existing repository data",
        ),
        key_size: int = Arg(
            default=4096,
            help="Size of private key; defaults to 4096 bit",
        ),
    ):
        """Initialise a certificate authority."""

        ca = ResourceInput[CreateCA](CreateCA).input()

        passphrase = None
        while passphrase is None:
            phrase = Prompt.ask("Passphrase", password=True)
            check = Prompt.ask("Confirm Passphrase", password=True)
            if phrase != check:
                print("[red]Confirmation doesn't match[/red]")
            else:
                passphrase = phrase

        await CertificateRepository.create_selfsigned(
            ca, passphrase, FileSystemStorage(root), exist_ok=force, key_size=key_size
        )

    @staticmethod
    @group.command(name="root")
    async def export_root_certificate(
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        """Export the root certificate."""
        from cryptography.hazmat.primitives import serialization

        repo = await CertificateRepository.from_url(root)
        certificate = await repo.ca_certificate()
        print(certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"))


class Domains:
    group = APP.create_command_group(
        "domain", aliases=("d",), help_text="Actions for domains"
    )

    @staticmethod
    @group.command(aliases=("ls",))
    async def list(
        query: Optional[str] = Arg(default="*"),
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        """List all managed certificates"""
        repo = await CertificateRepository.from_url(root)
        domains = await repo.list_domains(query)
        print("\n".join(f"- {name}" for name in domains) if domains else "None!")

    @staticmethod
    @group.command(name="add", help_text="Add a domain")
    async def add_domain(
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        create_domain = ResourceInput[CreateDomain](CreateDomain).input()
        ca_passphrase = getpass("CA Passphrase:")

        repo = await CertificateRepository.from_url(root)
        async with repo.unlock(ca_passphrase):
            domain = await repo.create_domain(create_domain)

        print(domain)

    @staticmethod
    @group.command(name="show", help_text="Show an existing domain")
    async def show_domain(
        domain_name: str,
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        repo = await CertificateRepository.from_url(root)
        domain = await repo.get_domain(domain_name)

        print(domain)

    @staticmethod
    @group.command(name="renew", help_text="Renew an existing domain")
    async def renew_domain(
        domain_name: str,
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        ca_passphrase = getpass("CA Passphrase:")

        repo = await CertificateRepository.from_url(root)
        domain = await repo.get_domain(domain_name)
        async with repo.unlock(ca_passphrase):
            await domain.renew()

        print(domain)

    @staticmethod
    @group.command(name="export", help_text="Export certificate")
    async def export_domain(
        domain_name: str,
        *,
        root: Path = Arg(default=Path(), help="Root path of authority storage"),
    ):
        from cryptography.hazmat.primitives import serialization

        repo = await CertificateRepository.from_url(root)
        domain = await repo.get_domain(domain_name)

        print(
            domain.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        )
