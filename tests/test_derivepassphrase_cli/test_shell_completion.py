# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import contextlib
import json
import types
from typing import TYPE_CHECKING

import click.testing
import pytest
from typing_extensions import Any

from derivepassphrase import _types, cli
from derivepassphrase._internals import cli_helpers
from tests import data, machinery
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from collections.abc import Set as AbstractSet
    from typing import NoReturn

    from typing_extensions import Literal

DUMMY_SERVICE = data.DUMMY_SERVICE
DUMMY_CONFIG_SETTINGS = data.DUMMY_CONFIG_SETTINGS


def bash_format(item: click.shell_completion.CompletionItem) -> str:
    """A formatter for `bash`-style shell completion items.

    The format is `type,value`, and is dictated by [`click`][].

    """
    type, value = (  # noqa: A001
        item.type,
        item.value,
    )
    return f"{type},{value}"


def fish_format(item: click.shell_completion.CompletionItem) -> str:
    r"""A formatter for `fish`-style shell completion items.

    The format is `type,value<tab>help`, and is dictated by [`click`][].

    """
    type, value, help = (  # noqa: A001
        item.type,
        item.value,
        item.help,
    )
    return f"{type},{value}\t{help}" if help else f"{type},{value}"


def zsh_format(item: click.shell_completion.CompletionItem) -> str:
    r"""A formatter for `zsh`-style shell completion items.

    The format is `type<newline>value<newline>help<newline>`, and is
    dictated by [`click`][].  Upstream `click` currently (v8.2.0) does
    not deal with colons in the value correctly when the help text is
    non-degenerate.  Our formatter here does, provided the upstream
    `zsh` completion script is used; see the
    [`cli_machinery.ZshComplete`][] class.  A request is underway to
    merge this change into upstream `click`; see
    [`pallets/click#2846`][PR2846].

    [PR2846]: https://github.com/pallets/click/pull/2846

    """
    empty_help = "_"
    help_, value = (
        (item.help, item.value.replace(":", r"\:"))
        if item.help and item.help == empty_help
        else (empty_help, item.value)
    )
    return f"{item.type}\n{value}\n{help_}"


def completion_item(
    item: str | click.shell_completion.CompletionItem,
) -> click.shell_completion.CompletionItem:
    """Convert a string to a completion item, if necessary."""
    return (
        click.shell_completion.CompletionItem(item, type="plain")
        if isinstance(item, str)
        else item
    )


def assertable_item(
    item: str | click.shell_completion.CompletionItem,
) -> tuple[str, Any, str | None]:
    """Convert a completion item into a pretty-printable item.

    Intended to make completion items introspectable in pytest's
    `assert` output.

    """
    item = completion_item(item)
    return (item.type, item.value, item.help)


class Parametrize(types.SimpleNamespace):
    """Common test parametrizations."""

    COMPLETABLE_PATH_ARGUMENT = pytest.mark.parametrize(
        "command_prefix",
        [
            pytest.param(
                ("export", "vault"),
                id="derivepassphrase-export-vault",
            ),
            pytest.param(
                ("vault", "--export"),
                id="derivepassphrase-vault--export",
            ),
            pytest.param(
                ("vault", "--import"),
                id="derivepassphrase-vault--import",
            ),
        ],
    )
    COMPLETABLE_OPTIONS = pytest.mark.parametrize(
        ["command_prefix", "incomplete", "completions"],
        [
            pytest.param(
                (),
                "-",
                frozenset({
                    "--help",
                    "-h",
                    "--version",
                    "--debug",
                    "--verbose",
                    "-v",
                    "--quiet",
                    "-q",
                }),
                id="derivepassphrase",
            ),
            pytest.param(
                ("export",),
                "-",
                frozenset({
                    "--help",
                    "-h",
                    "--version",
                    "--debug",
                    "--verbose",
                    "-v",
                    "--quiet",
                    "-q",
                }),
                id="derivepassphrase-export",
            ),
            pytest.param(
                ("export", "vault"),
                "-",
                frozenset({
                    "--help",
                    "-h",
                    "--version",
                    "--debug",
                    "--verbose",
                    "-v",
                    "--quiet",
                    "-q",
                    "--format",
                    "-f",
                    "--key",
                    "-k",
                }),
                id="derivepassphrase-export-vault",
            ),
            pytest.param(
                ("vault",),
                "-",
                frozenset({
                    "--help",
                    "-h",
                    "--version",
                    "--debug",
                    "--verbose",
                    "-v",
                    "--quiet",
                    "-q",
                    "--phrase",
                    "-p",
                    "--key",
                    "-k",
                    "--length",
                    "-l",
                    "--repeat",
                    "-r",
                    "--upper",
                    "--lower",
                    "--number",
                    "--space",
                    "--dash",
                    "--symbol",
                    "--config",
                    "-c",
                    "--notes",
                    "-n",
                    "--delete",
                    "-x",
                    "--delete-globals",
                    "--clear",
                    "-X",
                    "--export",
                    "-e",
                    "--import",
                    "-i",
                    "--overwrite-existing",
                    "--merge-existing",
                    "--unset",
                    "--export-as",
                    "--modern-editor-interface",
                    "--vault-legacy-editor-interface",
                    "--print-notes-before",
                    "--print-notes-after",
                }),
                id="derivepassphrase-vault",
            ),
        ],
    )
    COMPLETABLE_SUBCOMMANDS = pytest.mark.parametrize(
        ["command_prefix", "incomplete", "completions"],
        [
            pytest.param(
                (),
                "",
                frozenset({"export", "vault"}),
                id="derivepassphrase",
            ),
            pytest.param(
                ("export",),
                "",
                frozenset({"vault"}),
                id="derivepassphrase-export",
            ),
        ],
    )
    COMPLETION_FUNCTION_INPUTS = pytest.mark.parametrize(
        ["config", "comp_func", "args", "incomplete", "results"],
        [
            pytest.param(
                {"services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}},
                cli_helpers.shell_complete_service,
                ["vault"],
                "",
                [DUMMY_SERVICE],
                id="base_config-service",
            ),
            pytest.param(
                {"services": {}},
                cli_helpers.shell_complete_service,
                ["vault"],
                "",
                [],
                id="empty_config-service",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        "newline\nin\nname": DUMMY_CONFIG_SETTINGS.copy(),
                    }
                },
                cli_helpers.shell_complete_service,
                ["vault"],
                "",
                [DUMMY_SERVICE],
                id="incompletable_newline_config-service",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        "backspace\bin\bname": DUMMY_CONFIG_SETTINGS.copy(),
                    }
                },
                cli_helpers.shell_complete_service,
                ["vault"],
                "",
                [DUMMY_SERVICE],
                id="incompletable_backspace_config-service",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        "colon:in:name": DUMMY_CONFIG_SETTINGS.copy(),
                    }
                },
                cli_helpers.shell_complete_service,
                ["vault"],
                "",
                sorted([DUMMY_SERVICE, "colon:in:name"]),
                id="brittle_colon_config-service",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy(),
                        "colon:in:name": DUMMY_CONFIG_SETTINGS.copy(),
                        "newline\nin\nname": DUMMY_CONFIG_SETTINGS.copy(),
                        "backspace\bin\bname": DUMMY_CONFIG_SETTINGS.copy(),
                        "nul\x00in\x00name": DUMMY_CONFIG_SETTINGS.copy(),
                        "del\x7fin\x7fname": DUMMY_CONFIG_SETTINGS.copy(),
                    }
                },
                cli_helpers.shell_complete_service,
                ["vault"],
                "",
                sorted([DUMMY_SERVICE, "colon:in:name"]),
                id="brittle_incompletable_multi_config-service",
            ),
            pytest.param(
                {"services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS.copy()}},
                cli_helpers.shell_complete_path,
                ["vault", "--import"],
                "",
                [click.shell_completion.CompletionItem("", type="file")],
                id="base_config-path",
            ),
            pytest.param(
                {"services": {}},
                cli_helpers.shell_complete_path,
                ["vault", "--import"],
                "",
                [click.shell_completion.CompletionItem("", type="file")],
                id="empty_config-path",
            ),
        ],
    )
    COMPLETABLE_SERVICE_NAMES = pytest.mark.parametrize(
        ["config", "incomplete", "completions"],
        [
            pytest.param(
                {"services": {}},
                "",
                frozenset(),
                id="no_services",
            ),
            pytest.param(
                {"services": {}},
                "partial",
                frozenset(),
                id="no_services_partial",
            ),
            pytest.param(
                {"services": {DUMMY_SERVICE: {"length": 10}}},
                "",
                frozenset({DUMMY_SERVICE}),
                id="one_service",
            ),
            pytest.param(
                {"services": {DUMMY_SERVICE: {"length": 10}}},
                DUMMY_SERVICE[:4],
                frozenset({DUMMY_SERVICE}),
                id="one_service_partial",
            ),
            pytest.param(
                {"services": {DUMMY_SERVICE: {"length": 10}}},
                DUMMY_SERVICE[-4:],
                frozenset(),
                id="one_service_partial_miss",
            ),
        ],
    )
    SERVICE_NAME_COMPLETION_INPUTS = pytest.mark.parametrize(
        ["config", "key", "incomplete", "completions"],
        [
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "newline\nin\nname": {"length": 10},
                    },
                },
                "newline\nin\nname",
                "",
                frozenset({DUMMY_SERVICE}),
                id="newline",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "newline\nin\nname": {"length": 10},
                    },
                },
                "newline\nin\nname",
                "serv",
                frozenset({DUMMY_SERVICE}),
                id="newline_partial_other",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "newline\nin\nname": {"length": 10},
                    },
                },
                "newline\nin\nname",
                "newline",
                frozenset({}),
                id="newline_partial_specific",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "nul\x00in\x00name": {"length": 10},
                    },
                },
                "nul\x00in\x00name",
                "",
                frozenset({DUMMY_SERVICE}),
                id="nul",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "nul\x00in\x00name": {"length": 10},
                    },
                },
                "nul\x00in\x00name",
                "serv",
                frozenset({DUMMY_SERVICE}),
                id="nul_partial_other",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "nul\x00in\x00name": {"length": 10},
                    },
                },
                "nul\x00in\x00name",
                "nul",
                frozenset({}),
                id="nul_partial_specific",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "backspace\bin\bname": {"length": 10},
                    },
                },
                "backspace\bin\bname",
                "",
                frozenset({DUMMY_SERVICE}),
                id="backspace",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "backspace\bin\bname": {"length": 10},
                    },
                },
                "backspace\bin\bname",
                "serv",
                frozenset({DUMMY_SERVICE}),
                id="backspace_partial_other",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "backspace\bin\bname": {"length": 10},
                    },
                },
                "backspace\bin\bname",
                "back",
                frozenset({}),
                id="backspace_partial_specific",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "del\x7fin\x7fname": {"length": 10},
                    },
                },
                "del\x7fin\x7fname",
                "",
                frozenset({DUMMY_SERVICE}),
                id="del",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "del\x7fin\x7fname": {"length": 10},
                    },
                },
                "del\x7fin\x7fname",
                "serv",
                frozenset({DUMMY_SERVICE}),
                id="del_partial_other",
            ),
            pytest.param(
                {
                    "services": {
                        DUMMY_SERVICE: {"length": 10},
                        "del\x7fin\x7fname": {"length": 10},
                    },
                },
                "del\x7fin\x7fname",
                "del",
                frozenset({}),
                id="del_partial_specific",
            ),
        ],
    )
    SERVICE_NAME_EXCEPTIONS = pytest.mark.parametrize(
        "exc_type", [RuntimeError, KeyError, ValueError]
    )
    INCOMPLETE = pytest.mark.parametrize("incomplete", ["", "partial"])
    CONFIG_SETTING_MODE = pytest.mark.parametrize("mode", ["config", "import"])
    COMPLETABLE_ITEMS = pytest.mark.parametrize(
        ["partial", "is_completable"],
        [
            ("", True),
            (DUMMY_SERVICE, True),
            ("a\bn", False),
            ("\b", False),
            ("\x00", False),
            ("\x20", True),
            ("\x7f", False),
            ("service with spaces", True),
            ("service\nwith\nnewlines", False),
        ],
    )
    SHELL_FORMATTER = pytest.mark.parametrize(
        ["shell", "format_func"],
        [
            pytest.param("bash", bash_format, id="bash"),
            pytest.param("fish", fish_format, id="fish"),
            pytest.param("zsh", zsh_format, id="zsh"),
        ],
    )


class TestShellCompletion:
    """Tests for the shell completion machinery."""

    class Completions:
        """A deferred completion call."""

        def __init__(
            self,
            args: Sequence[str],
            incomplete: str,
        ) -> None:
            """Initialize the object.

            Args:
                args:
                    The sequence of complete command-line arguments.
                incomplete:
                    The final, incomplete, partial argument.

            """
            self.args = tuple(args)
            self.incomplete = incomplete

        def __call__(self) -> Sequence[click.shell_completion.CompletionItem]:
            """Return the completion items."""
            args = list(self.args)
            completion = click.shell_completion.ShellComplete(
                cli=cli.derivepassphrase,
                ctx_args={},
                prog_name="derivepassphrase",
                complete_var="_DERIVEPASSPHRASE_COMPLETE",
            )
            return completion.get_completions(args, self.incomplete)

        def get_words(self) -> Sequence[str]:
            """Return the completion items' values, as a sequence."""
            return tuple(c.value for c in self())


class TestCompletableItems:
    """Tests for completablility of items."""

    @Parametrize.COMPLETABLE_ITEMS
    def test_is_completable_item(
        self,
        partial: str,
        is_completable: bool,
    ) -> None:
        """Our `_is_completable_item` predicate for service names works."""
        assert cli_helpers.is_completable_item(partial) == is_completable


class TestCompletableItemClasses(TestShellCompletion):
    """Tests for the different classes of completable items."""

    @Parametrize.COMPLETABLE_OPTIONS
    def test_options(
        self,
        command_prefix: Sequence[str],
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Our completion machinery works for all commands' options."""
        comp = self.Completions(command_prefix, incomplete)
        assert frozenset(comp.get_words()) == completions

    @Parametrize.COMPLETABLE_SUBCOMMANDS
    def test_subcommands(
        self,
        command_prefix: Sequence[str],
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Our completion machinery works for all commands' subcommands."""
        comp = self.Completions(command_prefix, incomplete)
        assert frozenset(comp.get_words()) == completions

    @Parametrize.COMPLETABLE_PATH_ARGUMENT
    @Parametrize.INCOMPLETE
    def test_paths(
        self,
        command_prefix: Sequence[str],
        incomplete: str,
    ) -> None:
        """Our completion machinery works for all commands' paths."""
        file = click.shell_completion.CompletionItem("", type="file")
        completions = frozenset({(file.type, file.value, file.help)})
        comp = self.Completions(command_prefix, incomplete)
        assert (
            frozenset((x.type, x.value, x.help) for x in comp()) == completions
        )

    @Parametrize.COMPLETABLE_SERVICE_NAMES
    def test_service_names(
        self,
        config: _types.VaultConfig,
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Our completion machinery works for vault service names."""
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            comp = self.Completions(["vault"], incomplete)
            assert frozenset(comp.get_words()) == completions


class TestCompletionFormatting:
    """Tests for the formatting of completable items."""

    @Parametrize.SHELL_FORMATTER
    @Parametrize.COMPLETION_FUNCTION_INPUTS
    def test_shell_completion_formatting(
        self,
        shell: str,
        format_func: Callable[[click.shell_completion.CompletionItem], str],
        config: _types.VaultConfig,
        comp_func: Callable[
            [click.Context, click.Parameter, str],
            list[str | click.shell_completion.CompletionItem],
        ],
        args: list[str],
        incomplete: str,
        results: list[str | click.shell_completion.CompletionItem],
    ) -> None:
        """Custom completion functions work for all shells."""
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=config,
                )
            )
            expected_items = [assertable_item(item) for item in results]
            expected_string = "\n".join(
                format_func(completion_item(item)) for item in results
            )
            manual_raw_items = comp_func(
                click.Context(cli.derivepassphrase),
                click.Argument(["sample_parameter"]),
                incomplete,
            )
            manual_items = [assertable_item(item) for item in manual_raw_items]
            manual_string = "\n".join(
                format_func(completion_item(item)) for item in manual_raw_items
            )
            assert manual_items == expected_items
            assert manual_string == expected_string
            comp_class = click.shell_completion.get_completion_class(shell)
            assert comp_class is not None
            comp = comp_class(
                cli.derivepassphrase,
                {},
                "derivepassphrase",
                "_DERIVEPASSPHRASE_COMPLETE",
            )
            monkeypatch.setattr(
                comp,
                "get_completion_args",
                lambda *_a, **_kw: (args, incomplete),
            )
            actual_raw_items = comp.get_completions(
                *comp.get_completion_args()
            )
            actual_items = [assertable_item(item) for item in actual_raw_items]
            actual_string = comp.complete()
            assert actual_items == expected_items
            assert actual_string == expected_string


class TestCLICompletabilityHandling(TestShellCompletion):
    """Tests for how the command-line interface handles completability."""

    @Parametrize.CONFIG_SETTING_MODE
    @Parametrize.SERVICE_NAME_COMPLETION_INPUTS
    def test_cli_warns_and_completion_skips_incompletable_service_names(
        self,
        caplog: pytest.LogCaptureFixture,
        mode: Literal["config", "import"],
        config: _types.VaultConfig,
        key: str,
        incomplete: str,
        completions: AbstractSet[str],
    ) -> None:
        """Completion skips incompletable items."""
        vault_config = config if mode == "config" else {"services": {}}
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config=vault_config,
                )
            )
            if mode == "config":
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    ["--config", "--length=10", "--", key],
                    catch_exceptions=False,
                )
            else:
                result = runner.invoke(
                    cli.derivepassphrase_vault,
                    ["--import", "-"],
                    catch_exceptions=False,
                    input=json.dumps(config),
                )
            assert result.clean_exit(), "expected clean exit"
            assert machinery.warning_emitted(
                "contains an ASCII control character", caplog.record_tuples
            ), "expected known warning message in stderr"
            assert machinery.warning_emitted(
                "not be available for completion", caplog.record_tuples
            ), "expected known warning message in stderr"
            assert cli_helpers.load_config() == config
            comp = self.Completions(["vault"], incomplete)
            assert frozenset(comp.get_words()) == completions

    def test_handling_nonexistant_service_names(
        self,
    ) -> None:
        """Service name completion quietly fails on missing configuration."""
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={
                        "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
                    },
                )
            )
            cli_helpers.config_filename(subsystem="vault").unlink(
                missing_ok=True
            )
            assert not cli_helpers.shell_complete_service(
                click.Context(cli.derivepassphrase),
                click.Argument(["some_parameter"]),
                "",
            )

    @Parametrize.SERVICE_NAME_EXCEPTIONS
    def test_handling_unexpected_exceptions(
        self,
        exc_type: type[Exception],
    ) -> None:
        """Service name completion quietly fails on configuration errors."""
        runner = machinery.CliRunner(mix_stderr=False)
        # TODO(the-13th-letter): Rewrite using parenthesized
        # with-statements.
        # https://the13thletter.info/derivepassphrase/latest/pycompatibility/#after-eol-py3.9
        with contextlib.ExitStack() as stack:
            monkeypatch = stack.enter_context(pytest.MonkeyPatch.context())
            stack.enter_context(
                pytest_machinery.isolated_vault_config(
                    monkeypatch=monkeypatch,
                    runner=runner,
                    vault_config={
                        "services": {DUMMY_SERVICE: DUMMY_CONFIG_SETTINGS}
                    },
                )
            )

            def raiser(*_a: Any, **_kw: Any) -> NoReturn:
                raise exc_type("just being difficult")  # noqa: EM101,TRY003

            monkeypatch.setattr(cli_helpers, "load_config", raiser)
            assert not cli_helpers.shell_complete_service(
                click.Context(cli.derivepassphrase),
                click.Argument(["some_parameter"]),
                "",
            )
