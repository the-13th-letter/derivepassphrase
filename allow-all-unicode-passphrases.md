# `derivepassphrase` bug allow-all-unicode-passphrases

???+ bug-success "Bug details: Allow all Unicode text strings as master passphrases"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>bug</i><td>This is clearly an actual problem we want fixed.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 0.1.2 <b>0.1.3</b>
        <tr><th scope=col>Fixed-in<td colspan=2><a href="https://github.com/the-13th-letter/derivepassphrase/commit/aacd09bdcbdb01df7cb819396727d2427636b144">aacd09bdcbdb01df7cb819396727d2427636b144</a> (0.2.0)
    </table>

In v0.1.x, `derivepassphrase` will accept a textual master passphrase if and only if it has a unique Unicode normalization form, i.e. if the NFC- and NFD-normalized forms of the master passphrase agree. This check was intended to safeguard against a passphrase from the configuration file being interpreted incorrectly by the `Vault` constructor (and subsequently generating the wrong passphrase) because it derived the wrong normalized form as the binary input string to the `vault` algorithm.

This understanding of the "derived the wrong normalized form" part turns out to be wrong: the encoding of textual string to binary string is unique, and the ambiguity in the textual master passphrase arises only when reading the master passphrase *as text*. No matter what text is stored as the master passphrase, its binary encoding is unique, and is valid input to the `vault` algorithm. However, there is value in warning the user that the stored textual passphrase may not be what they think it is, because they are being misled by their editor, or copy-pasting the configuration from somewhere else.

<b>Next steps:</b>

1. Remove the machinery that asserts a unique normalization form. In particular, remove the `Vault.AmbiguousByteRepresentationError` exception type.
2. Remove the check for unique normalization form from the `Vault` constructor. Instead, add a warning during the `--import` and `--config` modes of operation when the config file has unnormalized or incorrectly normalized stored master passphrases.
3. Add a new configuration item, presumably `.global.unicode_normalization_form` and defaulting to `NFC`, from which to obtain the correct normalization form.

--------

> 2. Remove the check for unique normalization form from the `Vault` constructor. Instead, add a warning during the `--import` and `--config` modes of operation when the config file has unnormalized or incorrectly normalized stored master passphrases.

Actually, the warning is equally sensible when interactively entering a master passphrase, not just when updating the configuration.
