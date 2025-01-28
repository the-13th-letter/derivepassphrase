### Added

  - [`Vault`][derivepassphrase.vault.Vault] now can report on whether two
    master passphrases are interchangable with respect to the service
    passphrases they can derive.
    This is an artefact of how the master passphrase is converted to the
    random bit sequence with which the service passphrases are generated.
    See the corresponding [FAQ entry: What are "interchangable passphrases"
    in vault?][INTERCHANGABLE_PASSPHRASES] for details, including the
    practical security (non-)implications.

    The `derivepassphrase vault` command-line interface does not address
    this in any manner, mostly because the "non-standard" interchangable
    variants of a given master password tend to be ugly to type in, and
    because they do not have practical security implications.

[INTERCHANGABLE_PASSPHRASES]: ../explanation/faq-vault-interchangable-passphrases.md
