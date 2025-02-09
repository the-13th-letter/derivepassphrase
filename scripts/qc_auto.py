#!/usr/bin/python3
# SPDX-FileCopyrightText: 2025 Marco Ricci <software@the13thletter.info>
#
# SPDX-License-Identifier: Zlib

# ruff: noqa: S404,S603,S607

"""Run various quality control checks automatically.

Distinguish between the master branch and other branches: run the full
test suite and build the documentation only on the master branch,
otherwise use only a reduced set of test environments and don't build
the documentation at all.  In both cases, run the linter, the formatter,
and the type checker.

If we are currently in a Stacked Git patch queue, do not run any tests,
do not run the type checker and do not build the documentation.  These
all slow down patch refreshing to a grinding halt, and will be checked
afterwards anyway when merging the patch queue back into the master
branch.  Stick to formatting and linting only.

"""

import os
import subprocess
import sys

envs = ['3.9', '3.11', '3.13', 'pypy3.10']
opts = ['-py', ','.join(envs)]

current_branch = subprocess.run(
    ['git', 'branch', '--show-current'],
    capture_output=True,
    text=True,
    check=False,
).stdout.strip()
# We use rev-parse to check for Stacked Git's metadata tracking branch,
# instead of checking `stg top` or similar, because we also want the
# first `stg new` or `stg import` to correctly detect that we are
# working on a patch queue.
is_stgit_patch = bool(
    subprocess.run(
        [
            'git',
            'rev-parse',
            '--verify',
            '--end-of-options',
            f'refs/stacks/{current_branch}',
        ],
        capture_output=True,
        check=False,
    ).stdout
)

try:
    # In a first run, ignore E501 (line-too-long) and RUF100
    # (unused-noqa), so that E501 errors don't stop the formatter from
    # running, but also so that E501 noqas don't get fixed as RUF100
    # violations.  Afterwards, run with normal settings to handle true
    # E501s.
    subprocess.run(
        ['hatch', 'fmt', '-l', '--', '--ignore=E501,RUF100'], check=True
    )
    subprocess.run(['hatch', 'fmt', '-f'], check=True)
    subprocess.run(['hatch', 'fmt', '-l'], check=True)
    if current_branch == 'master':
        subprocess.run(
            ['hatch', 'env', 'run', '-e', 'types', '--', 'check'], check=True
        )
        subprocess.run(
            ['hatch', 'test', '-acpqr', '--', '--maxfail', '1'],
            check=True,
        )
        # fmt: off
        subprocess.run(
            [
                'hatch', 'env', 'run', '-e', 'docs', '--',
                'build', '-f', 'mkdocs_devsetup.yaml',
            ],
            check=True,
        )
        # fmt: on
    elif not is_stgit_patch:
        subprocess.run(
            ['hatch', 'env', 'run', '-e', 'types', '--', 'check'], check=True
        )
        subprocess.run(
            ['hatch', 'test', '-cpqr', *opts, '--', '--maxfail', '1'],
            env={**os.environ} | {'HYPOTHESIS_PROFILE': 'dev'},
            check=True,
        )
except subprocess.CalledProcessError as exc:
    sys.exit(getattr(exc, 'returncode', 1))
except KeyboardInterrupt:
    sys.exit(1)
