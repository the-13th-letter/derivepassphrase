# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

"""Tests for the `derivepassphrase vault` command-line interface: notes handling."""

from __future__ import annotations

import contextlib
import json
import types
from typing import TYPE_CHECKING

import click.testing
import hypothesis
import pytest
from hypothesis import strategies
from typing_extensions import Any, TypedDict

from derivepassphrase import _types, cli
from derivepassphrase._internals import (
    cli_helpers,
    cli_messages,
)
from tests import data, machinery
from tests.machinery import pytest as pytest_machinery

if TYPE_CHECKING:
    from typing import NoReturn

    from typing_extensions import Literal, NotRequired

DUMMY_SERVICE = data.DUMMY_SERVICE
DUMMY_PASSPHRASE = data.DUMMY_PASSPHRASE
DUMMY_CONFIG_SETTINGS = data.DUMMY_CONFIG_SETTINGS
DUMMY_RESULT_PASSPHRASE = data.DUMMY_RESULT_PASSPHRASE


def is_warning_line(line: str) -> bool:
    """Return true if the line is a warning line."""
    return " Warning: " in line or " Deprecation warning: " in line


class Strategies:
    @staticmethod
    def notes(*, max_size: int = 512) -> strategies.SearchStrategy[str]:
        return strategies.text(
            strategies.characters(
                min_codepoint=32, max_codepoint=126, include_characters="\n"
            ),
            min_size=1,
            max_size=max_size,
        )


class Parametrize(types.SimpleNamespace):
    """Common test parametrizations."""

    MODERN_EDITOR_INTERFACE = pytest.mark.parametrize(
        "modern_editor_interface", [False, True], ids=["legacy", "modern"]
    )
    NOTES_PLACEMENT = pytest.mark.parametrize(
        ["notes_placement", "placement_args"],
        [
            pytest.param("after", ["--print-notes-after"], id="after"),
            pytest.param("before", ["--print-notes-before"], id="before"),
        ],
    )


class TestNotesPrinting:
    """Tests concerning printing the service notes."""

    def _test(
        self,
        notes: str,
        /,
        notes_placement: Literal["before", "after"] | None = None,
        placement_args: list[str] | tuple[str, ...] = (),
    ) -> None:
        notes_stripped = notes.strip()
        maybe_notes = {"notes": notes_stripped} if notes_stripped else {}
        vault_config = {
            "global": {"phrase": DUMMY_PASSPHRASE},
            "services": {
                DUMMY_SERVICE: {**maybe_notes, **DUMMY_CONFIG_SETTINGS}
            },
        }
        result_phrase = DUMMY_RESULT_PASSPHRASE.decode("ascii")
        expected = (
            f"{notes_stripped}\n\n{result_phrase}\n"
            if notes_placement == "before"
            else f"{result_phrase}\n\n{notes_stripped}\n\n"
            if notes_placement == "after"
            else None
        )
        runner = machinery.CliRunner(mix_stderr=notes_placement is not None)
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
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [*placement_args, "--", DUMMY_SERVICE],
                catch_exceptions=False,
            )
            if expected is not None:
                assert result.clean_exit(output=expected), (
                    "expected clean exit"
                )
            else:
                assert result.clean_exit(), "expected clean exit"
                assert result.stdout, "expected program output"
                assert result.stdout.strip() == result_phrase, (
                    "expected known program output"
                )
                assert result.stderr or not notes_stripped, "expected stderr"
                assert "Error:" not in result.stderr, (
                    "expected no error messages on stderr"
                )
                assert result.stderr.strip() == notes_stripped, (
                    "expected known stderr contents"
                )

    @hypothesis.given(notes=Strategies.notes())
    def test_service_with_notes_actually_prints_notes(
        self,
        notes: str,
    ) -> None:
        """Service notes are printed, if they contain content.

        (Service notes are trimmed before printing, and thus result in
        output if and only if they are non-empty after trimming leading
        and trailing whitespace.)

        """
        hypothesis.assume("Error:" not in notes)
        self._test(notes, notes_placement=None, placement_args=())

    @Parametrize.NOTES_PLACEMENT
    @hypothesis.given(notes=Strategies.notes().filter(str.strip))
    @hypothesis.example(notes="  ").xfail(
        reason="empty notes", raises=AssertionError
    )
    def test_notes_placement(
        self,
        notes_placement: Literal["before", "after"],
        placement_args: list[str],
        notes: str,
    ) -> None:
        self._test(
            notes,
            notes_placement=notes_placement,
            placement_args=placement_args,
        )


class TestNotesEditing:
    """Superclass for tests concerning editing service notes."""

    CURRENT_NOTES = "Contents go here"
    OLD_NOTES_TEXT = (
        "These backup notes are left over from the previous session."
    )

    def _calculate_expected_contents(
        self,
        final_notes: str,
        /,
        *,
        modern_editor_interface: bool,
        current_notes: str | None = CURRENT_NOTES,
        old_notes_text: str | None = OLD_NOTES_TEXT,
    ) -> tuple[str, str]:
        current_notes = current_notes or ""
        old_notes_text = old_notes_text or ""
        # For the modern editor interface, the notes change if and only
        # if the notes change to a different, non-empty string.  There
        # are no backup notes, so we return the old ones (which may be
        # synthetic) unchanged.
        if modern_editor_interface:
            return old_notes_text.strip(), (
                final_notes.strip()
                if final_notes.strip()
                and final_notes.strip() != current_notes.strip()
                else current_notes.strip()
            )
        # For the legacy editor interface, the notes and the backup
        # notes change if and only if the new notes differ from the
        # previous notes.
        return (
            (current_notes.strip(), final_notes.strip())
            if final_notes.strip() != current_notes.strip()
            else (old_notes_text.strip(), current_notes.strip())
        )

    def _test(
        self,
        edit_result: str,
        /,
        *,
        modern_editor_interface: bool,
        current_notes: str | None = CURRENT_NOTES,
        old_notes_text: str | None = OLD_NOTES_TEXT,
    ) -> tuple[machinery.ReadableResult, str, _types.VaultConfig]:
        if hypothesis.currently_in_test_context():  # pragma: no branch
            hypothesis.note(f"{edit_result = }")
            hypothesis.note(f"{modern_editor_interface = }")
            hypothesis.note(
                f"vault_config = {self._vault_config(current_notes or '')}"
            )
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
                    vault_config=self._vault_config(current_notes or ""),
                )
            )
            notes_backup_file = cli_helpers.config_filename(
                subsystem="notes backup"
            )
            if old_notes_text and old_notes_text.strip():  # pragma: no branch
                notes_backup_file.write_text(
                    old_notes_text.strip(), encoding="UTF-8"
                )
            monkeypatch.setattr(click, "edit", lambda *_a, **_kw: edit_result)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    "--config",
                    "--notes",
                    "--modern-editor-interface"
                    if modern_editor_interface
                    else "--vault-legacy-editor-interface",
                    "--",
                    "sv",
                ],
                catch_exceptions=False,
            )
            backup_contents = notes_backup_file.read_text(encoding="UTF-8")
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            if hypothesis.currently_in_test_context():  # pragma: no branch
                hypothesis.note(f"{result = }")
                hypothesis.note(f"{backup_contents = }")
                hypothesis.note(f"{config = }")
            return result, backup_contents, config

    def _assert_noop_exit(
        self,
        result: machinery.ReadableResult,
        /,
        *,
        modern_editor_interface: bool = False,
    ) -> None:
        # We do not distinguish between aborts and no-op edits.  Aborts
        # are treated as failures (error exit), and thus tested
        # specifically in a different class.
        if modern_editor_interface:
            assert result.error_exit(
                error="the user aborted the request"
            ) or result.clean_exit(empty_stderr=True), "expected clean exit"
        else:
            assert result.clean_exit(empty_stderr=False), "expected clean exit"

    def _assert_normal_exit(self, result: machinery.ReadableResult) -> None:
        assert result.clean_exit(), "expected clean exit"
        assert all(map(is_warning_line, result.stderr.splitlines(True)))

    def _assert_notes_backup_warning(
        self,
        caplog: pytest.LogCaptureFixture,
        /,
        *,
        modern_editor_interface: bool,
        notes_unchanged: bool = False,
    ) -> None:
        assert (
            modern_editor_interface
            or notes_unchanged
            or machinery.warning_emitted(
                "A backup copy of the old notes was saved",
                caplog.record_tuples,
            )
        ), "expected known warning message on stderr"

    def _assert_notes_and_backup_notes(
        self,
        /,
        *,
        final_notes: str,
        new_backup_notes: str,
        new_config: _types.VaultConfig,
        modern_editor_interface: bool,
        current_notes: str | None = CURRENT_NOTES,
        old_notes_text: str | None = OLD_NOTES_TEXT,
    ) -> None:
        if hypothesis.currently_in_test_context():  # pragma: no branch
            hypothesis.note(f"{final_notes = }")
            hypothesis.note(f"{current_notes = }")
        expected_backup_notes, expected_notes = (
            self._calculate_expected_contents(
                final_notes,
                modern_editor_interface=modern_editor_interface,
                current_notes=current_notes,
                old_notes_text=old_notes_text,
            )
        )
        expected_config = self._vault_config(expected_notes)
        assert new_config == expected_config
        assert new_backup_notes == expected_backup_notes

    @staticmethod
    def _vault_config(
        starting_notes: str = CURRENT_NOTES, /
    ) -> _types.VaultConfig:
        return {
            "global": {"phrase": "abc"},
            "services": {
                "sv": {"notes": starting_notes.strip()}
                if starting_notes.strip()
                else {}
            },
        }

    class ExtraArgs(TypedDict):
        modern_editor_interface: bool
        current_notes: NotRequired[str]
        old_notes_text: NotRequired[str]


class TestNotesEditingValid(TestNotesEditing):
    """Tests concerning editing service notes: valid calls."""

    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(
        notes=Strategies
        .notes()
        .filter(str.strip)
        .filter(lambda notes: notes != TestNotesEditingValid.CURRENT_NOTES)
    )
    @hypothesis.example(TestNotesEditing.CURRENT_NOTES)
    @hypothesis.example(notes="  ").xfail(
        reason="empty notes", raises=AssertionError
    )
    def test_successful_edit(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Editing notes works."""
        # Reset caplog between hypothesis runs.
        caplog.clear()
        marker = cli_messages.TranslatedString(
            cli_messages.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
        )
        edit_result = (
            f"""

{marker}
{notes}
"""
            if modern_editor_interface
            else notes.strip()
        )

        extra_args: TestNotesEditing.ExtraArgs = {
            "modern_editor_interface": modern_editor_interface,
            "current_notes": self.CURRENT_NOTES,
            "old_notes_text": self.OLD_NOTES_TEXT,
        }
        notes_unchanged = notes.strip() == extra_args["current_notes"].strip()

        result, new_backup_notes, new_config = self._test(
            edit_result, **extra_args
        )
        self._assert_normal_exit(result)
        self._assert_notes_and_backup_notes(
            final_notes=notes,
            new_backup_notes=new_backup_notes,
            new_config=new_config,
            **extra_args,
        )
        self._assert_notes_backup_warning(
            caplog,
            modern_editor_interface=modern_editor_interface,
            notes_unchanged=notes_unchanged,
        )

    # TODO(the-13th-letter): Investigate behavior with respect to
    # whitespace-only notes and the legacy editor interface.
    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(notes=Strategies.notes().filter(str.strip))
    @hypothesis.example(TestNotesEditing.CURRENT_NOTES)
    def test_noop_edit(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """No-op editing existing notes works.

        The notes are unchanged, and the command-line interface does not
        report an abort.  For the legacy editor interface, the backup
        notes are unchanged as well.

        """
        # Reset caplog between hypothesis runs.
        caplog.clear()
        marker = cli_messages.TranslatedString(
            cli_messages.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
        )
        edit_result = (f"{marker}\n" if modern_editor_interface else "") + (
            " " * 6 + notes + "\n" * 6
        )

        extra_args: TestNotesEditing.ExtraArgs = {
            "modern_editor_interface": modern_editor_interface,
            "current_notes": notes.strip(),
            "old_notes_text": self.OLD_NOTES_TEXT,
        }

        result, new_backup_notes, new_config = self._test(
            edit_result, **extra_args
        )
        self._assert_noop_exit(
            result,
            modern_editor_interface=modern_editor_interface,
        )
        self._assert_notes_and_backup_notes(
            final_notes=notes,
            new_backup_notes=new_backup_notes,
            new_config=new_config,
            **extra_args,
        )
        self._assert_notes_backup_warning(
            caplog,
            modern_editor_interface=modern_editor_interface,
            notes_unchanged=True,
        )

    # TODO(the-13th-letter): Keep this behavior or not, with or without
    # warning?
    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(notes=Strategies.notes().filter(str.strip))
    @hypothesis.example(notes="  ").xfail(
        reason="empty notes", raises=AssertionError
    )
    def test_marker_removed(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Removing the notes marker still saves the notes.

        TODO: Keep this behavior or not, with or without warning?

        """
        notes_marker = cli_messages.TranslatedString(
            cli_messages.Label.DERIVEPASSPHRASE_VAULT_NOTES_MARKER
        )
        hypothesis.assume(str(notes_marker) not in notes.strip())
        # Reset caplog between hypothesis runs.
        caplog.clear()

        extra_args: TestNotesEditing.ExtraArgs = {
            "modern_editor_interface": modern_editor_interface,
            "current_notes": self.CURRENT_NOTES,
            "old_notes_text": self.OLD_NOTES_TEXT,
        }
        notes_unchanged = notes.strip() == extra_args["current_notes"].strip()

        result, new_backup_notes, new_config = self._test(
            notes.strip(), **extra_args
        )
        self._assert_normal_exit(result)
        self._assert_notes_and_backup_notes(
            final_notes=notes,
            new_backup_notes=new_backup_notes,
            new_config=new_config,
            **extra_args,
        )
        self._assert_notes_backup_warning(
            caplog,
            modern_editor_interface=modern_editor_interface,
            notes_unchanged=notes_unchanged,
        )


class TestNotesEditingInvalid(TestNotesEditing):
    """Tests concerning editing service notes: invalid/error calls."""

    @hypothesis.given(notes=Strategies.notes())
    @hypothesis.example(notes="")
    def test_abort(
        self,
        notes: str,
    ) -> None:
        """Aborting editing notes works, even if no notes are stored yet.

        Aborting is only supported with the modern editor interface.

        """
        edit_result = ""

        extra_args: TestNotesEditing.ExtraArgs = {
            "modern_editor_interface": True,
            "current_notes": notes.strip(),
            "old_notes_text": self.OLD_NOTES_TEXT,
        }

        result, new_backup_notes, new_config = self._test(
            edit_result, **extra_args
        )
        assert result.error_exit(error="the user aborted the request"), (
            "expected error exit"
        )
        self._assert_notes_and_backup_notes(
            final_notes=notes.strip(),
            new_backup_notes=new_backup_notes,
            new_config=new_config,
            **extra_args,
        )

    @Parametrize.MODERN_EDITOR_INTERFACE
    @hypothesis.settings(
        suppress_health_check=[
            *hypothesis.settings().suppress_health_check,
            hypothesis.HealthCheck.function_scoped_fixture,
        ],
    )
    @hypothesis.given(notes=Strategies.notes())
    @hypothesis.example(notes="")
    def test_fail_on_config_option_missing(
        self,
        caplog: pytest.LogCaptureFixture,
        modern_editor_interface: bool,
        notes: str,
    ) -> None:
        """Editing notes fails (and warns) if `--config` is missing."""
        maybe_notes = {"notes": notes.strip()} if notes.strip() else {}
        vault_config = {
            "global": {"phrase": DUMMY_PASSPHRASE},
            "services": {
                DUMMY_SERVICE: {**maybe_notes, **DUMMY_CONFIG_SETTINGS}
            },
        }
        old_notes_text = (
            "These backup notes are left over from the previous session."
        )
        # Reset caplog between hypothesis runs.
        caplog.clear()
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
            EDIT_ATTEMPTED = "edit attempted!"  # noqa: N806

            def raiser(*_args: Any, **_kwargs: Any) -> NoReturn:
                pytest.fail(EDIT_ATTEMPTED)

            notes_backup_file = cli_helpers.config_filename(
                subsystem="notes backup"
            )
            notes_backup_file.write_text(old_notes_text, encoding="UTF-8")
            monkeypatch.setattr(click, "edit", raiser)
            result = runner.invoke(
                cli.derivepassphrase_vault,
                [
                    "--notes",
                    "--modern-editor-interface"
                    if modern_editor_interface
                    else "--vault-legacy-editor-interface",
                    "--",
                    DUMMY_SERVICE,
                ],
                catch_exceptions=False,
            )
            assert result.clean_exit(
                output=DUMMY_RESULT_PASSPHRASE.decode("ascii")
            ), "expected clean exit"
            assert result.stderr
            assert notes.strip() in result.stderr
            assert all(
                is_warning_line(line)
                for line in result.stderr.splitlines(True)
                if line.startswith(f"{cli.PROG_NAME}: ")
            )
            assert machinery.warning_emitted(
                "Specifying --notes without --config is ineffective.  "
                "No notes will be edited.",
                caplog.record_tuples,
            ), "expected known warning message in stderr"
            assert (
                modern_editor_interface
                or notes_backup_file.read_text(encoding="UTF-8")
                == old_notes_text
            )
            with cli_helpers.config_filename(subsystem="vault").open(
                encoding="UTF-8"
            ) as infile:
                config = json.load(infile)
            assert config == vault_config
