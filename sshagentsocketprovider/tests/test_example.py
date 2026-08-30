# SPDX-FileCopyrightText: 2026 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

from __future__ import annotations

import subprocess
import sys
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    import pathlib

try:
    import venv
except ImportError:  # pragma: no cover
    pytest.skip(
        "Cannot test example package installation without virtualenv support",
        allow_module_level=True,
    )


@pytest.fixture
def isolated_venv_python(tmp_path: pathlib.Path) -> pathlib.Path:
    """Yield the path of the python executable in a newly created venv."""
    venv.create(tmp_path / "venv", with_pip=True)
    path_windows = tmp_path / "venv" / "Scripts" / "Python.exe"
    path_unix = tmp_path / "venv" / "bin" / "python"
    return path_windows if sys.platform == "win32" else path_unix


def is_project(path: pathlib.Path) -> bool:
    pyproject_toml = path / "pyproject.toml"
    return pyproject_toml.exists() and pyproject_toml.is_file()


def test_example_provider(
    request: pytest.FixtureRequest, isolated_venv_python: pathlib.Path
) -> None:
    rootdir = request.config.rootpath
    if not is_project(rootdir):
        pytest.skip(
            "Cannot install this project into a virtualenv "
            "without access to the project's pyproject.toml, "
            "but could not find any pyproject.toml at the pytest rootdir."
        )
    example_provider_project = (
        rootdir / "tests" / "fixtures" / "example-provider"
    )
    assert is_project(example_provider_project)

    install_step = subprocess.run(
        [
            str(isolated_venv_python),
            "-m",
            "pip",
            "-q",
            "--",
            "install",
            str(rootdir),
            str(example_provider_project),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    # Pass on output for debugging, *then* check the return code.
    sys.stdout.write(install_step.stdout)
    sys.stderr.write(install_step.stderr)
    install_step.check_returncode()

    check_file = isolated_venv_python.parent / "check.py"
    check_file.write_text(r"""
import importlib.metadata

import derivepassphrase_sshagentsocketprovider as d_sasp
from derivepassphrase_sshagentsocketprovider_example import stdin_stdout, failure_response, always_fail

expected_providers = [
    stdin_stdout.SSHAgentOverStdinStdoutSocket,
    failure_response.FailureSSHAgentSocket,
    always_fail.always_fail_socket_provider,
]
n = len(expected_providers)

entry_points = list(
    importlib.metadata.entry_points(group=d_sasp.ENTRY_POINT_GROUP_NAME)
)
assert len(entry_points) == n, f"expected exactly {n} entry points: {entry_points!r}"

for ep in entry_points:
    entry = ep.load()
    assert isinstance(entry, d_sasp.SSHAgentSocketProviderEntry), f"not an SSHAgentSocketProviderEntry: {entry!r}"
    assert isinstance(entry.provider, d_sasp.SSHAgentSocketProvider), f"not an SSHAgentSocketProvider: {entry.provider!r}"
    assert isinstance(entry.key, str), f"not a str: {entry.key!r}"
    assert isinstance(entry.aliases, tuple) and all(isinstance(x, str) for x in entry.aliases), f"not a tuple[str, ...]: {entry.aliases!r}"
    assert entry.provider in expected_providers, f"Unexpected provider: {entry.provider!r}"
    expected_providers.remove(entry.provider)

assert not expected_providers, f"Missing providers in entry points: {expected_providers!r}"
print("OK")
""")
    check_step = subprocess.run(
        [str(isolated_venv_python), str(check_file)],
        check=False,
        capture_output=True,
        text=True,
    )
    # Pass on output for debugging, *then* check the return code.
    sys.stdout.write(check_step.stdout)
    sys.stderr.write(check_step.stderr)
    check_step.check_returncode()
    assert not check_step.stderr.strip()
    assert check_step.stdout.strip() == "OK"
