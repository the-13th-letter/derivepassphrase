# Some ideas for future work

## Subcommands

(In no particular order.)

### Derivation schemes

* `spectre` (`master-password`): derive passphrases according to the "Master Password" scheme as used by the Spectre app. →[:material-file-document-plus-outline:][WISH_OTHER_DERIVATION_SCHEMES]

### Other functionality

* `explore-permitted-special-characters`: generate new configurations starting from a base configuration until one of them passes the "special characters" constraints.
* `rotate`: generate a new configuration suitable for passphrase rotation, compatible with the base configuration's constraints.
* `service-plugins`: manage plugins that automate certain tasks, as outlined in the notes of the queried service.

    * `load-ssh-key`: if the service uses an SSH key, autoload the key from a well-known location into the SSH agent if it isn't already loaded.

        `vault`-specific.

    * `decrypt-notes`: decrypt OpenPGP-encrypted notes with GnuPG or Sequoia `sq`.

        Open questions:

        - Use an automatic, symmetric encryption key, or rely on the standard OpenPGP key store?  (Do *not* use the derived service passphrase for this: the quality may be arbitrarily bad due to the passphrase constaints, and the service itself could compromise that passphrase.)

    * `generate-otp`: if the service uses two-factor authentication and the configuration contains one-time password settings, call `oathtool` to obtain one or more OTPs.

        May require the `decrypt-notes` plugin first.

    * `manage-runit-services`: if the service contains `runit` service configuration, ensure the specified `runit` services are running concurrently, and stopped after signalling.

        Typical use case is a service only accessible via VPN or SSH proxy, where the VPN/proxy would run as a `runit` service.

        Open questions:

        - Interface with `inotifywait` to wait for SSH control socket?

[WISH_OTHER_DERIVATION_SCHEMES]: wishlist/other-derivation-schemes.md "Wish entry: “Consider implementing passphrase schemes other than vault's”"

## Documentation

(Categorized as per [the diataxis framework][DIATAXIS], but otherwise in no particular order.)

[DIATAXIS]: https://diataxis.fr

### Tutorials

### How-tos

* How to choose a good service name

### Reference

### Explanation

* Security aspects and other tradeoffs when using deterministic password generators
* Should I use one master SSH key/master passphrase, or many? (→ [TODO][HOW_TO_SSH_KEY])
* Why is `vault`'s `--repeat` option named this way if it counts occurrences, not repetitions?

[BASIC_SETUP_PASSPHRASE]: tutorials/basic-setup-passphrase.md
[HOW_TO_SSH_KEY]: how-tos/ssh-key.md
