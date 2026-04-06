# Should I use one master SSH key/master passphrase, or many?

Generally, using multiple master SSH keys or master passphrases partitions the `derivepassphrase` configuration into sets such that the compromise of one master SSH key/master passphrase compromises all passphrases within that set of configurations.

However, using multiple master SSH keys or master passphrases also means that multiple SSH keys or passphrases must be managed.

## Multiple master SSH keys

Managing multiple master SSH keys is conceptually no different than managing a single key.

`derivepassphrase vault` can record which master SSH key to use for each configuration.

## Multiple master passphrases

Managing multiple master passphrases is somewhat more difficult.
The user must choose multiple high-quality master passphrases.
If passphrases are memorized (as is recommended), then this puts a much higher cognitive load on the user than keeping multiple master SSH keys.

Furthermore, `derivepassphrase vault` cannot record which master passphrase to use for each configuration, beyond storing the respective master passphrase itself (which is a **grave security risk**).
The user must thus find a different (usually out-of-band) way to associate each configuration with its matching master passphrase.

Due to these logistical difficulties, from a purely operational standpoint, using multiple master passphrases **is not recommended**.
