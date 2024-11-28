# Some ideas for future work

## Subcommands

(In no particular order.)

### Derivation schemes

* `spectre` (`master-password`): derive passphrases according to the "Master Password" scheme as used by the Spectre app. ([#2])

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

[#2]: https://github.com/the-13th-letter/derivepassphrase/issues/2

## Documentation

(Categorized as per [the diataxis framework][DIATAXIS], but otherwise in no particular order.)


[DIATAXIS]: https://diataxis.fr

### Tutorials

* [Setting up `derivepassphrase vault` from scratch for three existing accounts, with a master passphrase](tutorials/basic-setup-passphrase.md)

### How-tos

* [How to set up `derivepassphrase vault` with an SSH key](how-tos/ssh-key.md)
* How to choose a good service name
* How to edit a saved `derivepassphrase vault` configuration correctly
* How to deal with "supported" and "unsupported" special characters
* How to deal with regular passphrase rotation/rollover

### Reference

* `derivepassphrase-vault.json`(<b>5</b>)

### Explanation

* Security aspects and other tradeoffs when using deterministic password generators
* Tradeoffs between a master passphrase and a master SSH key
* Why is `vault`'s `--repeat` option named this way if it counts occurrences, not repetitions?
