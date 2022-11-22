"""Wrappers for working with resources at the CLI."""
from typing import TypeVar, Generic, Any

import odin
from odin.utils import getmeta
from rich import print
from rich.markdown import Markdown
from rich.prompt import Prompt
from rich.text import Text

_R = TypeVar("_R", bound=odin.Resource)


class ResourceInput(Generic[_R]):
    """Wrapper for a resource to be populated via a CLI."""

    def __init__(self, resource_type: type[_R], resource: _R | None = None):
        """Initialise resource input wrapper."""
        self.resource_type = resource_type
        self.resource = resource or resource_type()
        self._meta = getmeta(resource_type)

    def _get_field_default(self, field: odin.Field) -> Any:
        """Get default value for a field."""
        default_value = field.get_default()
        current_value = field.value_from_object(self.resource)
        return current_value or default_value

    def _process_field(self, field: odin.Field) -> Any:
        """Read a value from a field."""
        field_name = field.verbose_name
        default_value = self._get_field_default(field)

        while True:
            value = Prompt.ask(field_name, default=default_value)
            try:
                return field.clean(value)
            except odin.exceptions.ValidationError as ex:
                print_errors(ex)

    def input(self) -> _R:
        """Populate from input."""
        for field in self._meta.fields:
            value = self._process_field(field)
            field.value_to_object(self.resource, value)

        print_resource(self.resource)
        if Prompt.ask("OK?", choices=["y", "n"]) == "n":
            return self.input()

        return self.resource


def print_resource(resource: odin.Resource):
    """Print a resources."""
    meta = getmeta(resource)

    print()
    for field in meta.fields:
        value = field.value_from_object(resource)
        print(Text(f"- [cyan]{field.verbose_name}[/cyan]: {field.prepare(value)}"))


def print_errors(validation_error: odin.exceptions.ValidationError):
    """Print validation exceptions."""
    print(
        Markdown(
            "\n".join(
                f"- [red]{message}[/red]" for message in validation_error.messages
            )
        )
    )
