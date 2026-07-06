# Bugs & wishlist items

<small>(… a.k.a. "things to fix" and "things to add".)</small>

!!! abstract inline end "Legend: Formatting"
      - [scheduled for next release](index.md){: .scheduled-next }
      - [scheduled for some future release](index.md){: .scheduled }
      - [yet to be scheduled](index.md){: .unscheduled }

???+ bug "things to fix"
    <i>no entries</i>

???+ wish "things to add"
      - [remove-click][]{: .scheduled-next }
      - [no-strict-compatibility-mode][]{: .scheduled }
      - [conventional-configurable-text-styling][]{: .unscheduled }
      - [other-derivation-schemes][]{: .unscheduled }

??? bug-success "things fixed"
      - [allow-all-unicode-passphrases][]{: .fixed }
      - [amend-vault-config][]{: .fixed }
      - [better-error-messages][]{: .fixed }
      - [concurrency-audit][]{: .fixed }
      - [concurrency-testing-in-test-suite][]{: .fixed }
      - [configuration-directory-must-exist][]{: .fixed }
      - [fail-gracefully-without-af-unix][]{: .fixed }
      - [falsy-vault-config-values][]{: .fixed }
      - [no-stdlib-module-names][]{: .fixed }
      - [one-time-key-override-fails][]{: .fixed }
      - [openssh-bug3967-workaround][]{: .fixed }
      - [print-service-notes][]{: .fixed }
      - [remove-pageant-build-info-check][]{: .fixed }
      - [single-toplevel-module][]{: .fixed }
      - [test-filesystem-isolation][]{: .fixed }
      - [windows-ssh-agent-support][]{: .fixed }

??? wish-success "things added"

      - [export-vault-formats][]{: .fixed }
      - [exporter-script-as-subcommand][]{: .fixed }
      - [pretty-print-json][]{: .fixed }
      - [print-service-notes-above][]{: .fixed }
      - [report-build-flags-and-features][]{: .fixed }
      - [scheme-specific-cli-and-config][]{: .fixed }
      - [test-suite-isolated-ssh-agent][]{: .fixed }

??? note "About this wishlist"

    This is the list of bugs and wishes for `derivepassphrase`.
    It uses the same terminology and style as [PuTTY's wishlist][PUTTY_WISHLIST].
    By design, the list distinguishes solely between bugs and wishes, and focuses strongly on the facts, not on the plans for implementation.[^bug-tracking-concerns]
    The entries are named, not numbered, and the summaries are written by hand.

    The list is built statically; there is no interactive way to submit entries or commentary on an entry, or to run search queries against the entry database.
    To submit entries or commentary, contact the authors directly; see the website imprint and the embedded author info in version control.
    To run search queries or other automated queries against the entry database, check out the `wishlist` branch from version control and parse the entry files directly.

    See also the [entry format specification][ENTRY_SPEC].

[^bug-tracking-concerns]:
    See also the essay [Separation of concerns in a bug tracker][BUG_TRACKING_CONCERNS] by PuTTY's principal author, Simon Tatham.
    Like PuTTY, `derivepassphrase` is a "more serious free-software hobby project" developed by one principal author who also cannot definitively commit to any specific time plan.
    As such, `derivepassphrase` also does not have a formal plans table (beyond the very coarse <b>Priority</b> field).

  [allow-all-unicode-passphrases]: allow-all-unicode-passphrases.md
  [amend-vault-config]: amend-vault-config.md
  [better-error-messages]: better-error-messages.md
  [concurrency-audit]: concurrency-audit.md
  [concurrency-testing-in-test-suite]: concurrency-testing-in-test-suite.md
  [configuration-directory-must-exist]: configuration-directory-must-exist.md
  [conventional-configurable-text-styling]: conventional-configurable-text-styling.md
  [export-vault-formats]: export-vault-formats.md
  [exporter-script-as-subcommand]: exporter-script-as-subcommand.md
  [fail-gracefully-without-af-unix]: fail-gracefully-without-af-unix.md
  [falsy-vault-config-values]: falsy-vault-config-values.md
  [no-stdlib-module-names]: no-stdlib-module-names.md
  [no-strict-compatibility-mode]: no-strict-compatibility-mode.md
  [one-time-key-override-fails]: one-time-key-override-fails.md
  [openssh-bug3967-workaround]: openssh-bug3967-workaround.md
  [other-derivation-schemes]: other-derivation-schemes.md
  [pretty-print-json]: pretty-print-json.md
  [print-service-notes]: print-service-notes.md
  [print-service-notes-above]: print-service-notes-above.md
  [remove-click]: remove-click.md
  [remove-pageant-build-info-check]: remove-pageant-build-info-check.md
  [report-build-flags-and-features]: report-build-flags-and-features.md
  [scheme-specific-cli-and-config]: scheme-specific-cli-and-config.md
  [single-toplevel-module]: single-toplevel-module.md
  [test-filesystem-isolation]: test-filesystem-isolation.md
  [test-suite-isolated-ssh-agent]: test-suite-isolated-ssh-agent.md
  [windows-ssh-agent-support]: windows-ssh-agent-support.md

  [ENTRY_SPEC]: spec.md

  [PUTTY_WISHLIST]: https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/ "PuTTY Known Bugs and Wish List"
  [BUG_TRACKING_CONCERNS]: https://www.chiark.greenend.org.uk/~sgtatham/quasiblog/bugtracker-separate/ 'Simon Tatham: "Separation of concerns in a bug tracker"'
