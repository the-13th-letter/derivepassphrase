Release checklist
=================

???+ info "translations"

    1.  template: `python3 -m derivepassphrase._internals.cli_messages --template --set-version <VERSION> --set-build-time <DATE>`
    2.  idempotence of template
    3.  completeness: `msgmerge` on other `.po` files
    4.  `en_US@DEBUG` translations: `--debug-translation`
    5.  compile: `msgfmt`, then move output to the correct location, manually

???+ info "wishlist"

    1.  wishlist up to date?
    2. `master` references correct `wishlist` commit-ID?

???+ info "quality control"

    1.  `ruff format` / `hatch fmt -f`
    2.  `ruff check` / `hatch fmt -l`
    3.  `mypy` / `hatch run types:check`
    4.  `coverage -m pytest ...` / `hatch test -acpqr` (set `PYTHON_CPU_COUNT` and `HYPOTHESIS_PROFILE`)
    5.  move coverage database to different filename

???+ info "changelog"

    1.  `hatch run docs:scriv collect --add --edit --version <VERSION>`
    2.  fix header IDs, move & consolidate Markdown references at page bottom

???+ info "bump version, commit and tag"

    1.  `git add` all the above changes
    2.  `bump-my-version bump --current-version <OLD_VERSION> --new-version <NEW_VERSION>`

???+ info "update wishlist"

    1.  new version on all applicable open bugs/wishes
    2.  version marker for recently fixed bugs/wishes
    3.  `master` should reference correct `wishlist` commit-ID yet again

???+ info "build documentation"

    1.  `pypi-insiders server start` and `pypi-insiders update`, then maybe `hatch env remove docs`
    2.  `hatch run docs:mike deploy 0.x latest`

???+ info "publish"

    1.  publish to PyPI: `hatch clean && hatch build && hatch publish` (prepare credentials first)
    2.  upload documentation: `git worktree add doctree documentation-tree`, `coverage html --show-context --data-file=<COVERAGE-FILE>` (if desired), `rsync -aR --delete-after html/./ <HOST>`, `git worktree remove doctree`
    3.  publish source: `git push origin master wishlist documentation-tree`

