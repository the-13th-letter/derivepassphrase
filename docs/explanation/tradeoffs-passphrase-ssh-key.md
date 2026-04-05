# Tradeoffs between a master passphrase and a master SSH key

## Summary

<table markdown="1">
<thead>
<tr>
<th></th>
<th scope=col>master passphrase</th>
<th scope=col>master SSH key</th>
</tr>
</thead>
<tbody markdown="1">
<tr markdown="1">
<th scope=row>setup costs/system portability</th>
<td markdown="block">

  - requires `derivepassphrase` and its configuration, or any compatible system

</td>
<td markdown="block">

  - requires `derivepassphrase` and its configuration, or any compatible system
  - requires a running SSH agent supported by `derivepassphrase`
  - requires the master SSH key file, in a format supported by the SSH agent

</td>
</tr>
<tr markdown="1">
<th scope=row>resistance to brute force attacks</th>
<td markdown="block">

  - `derivepassphrase` configuration must be guessed
  - master passphrase must be guessed

</td>
<td markdown="block">

  - `derivepassphrase` configuration must be guessed
  - the master SSH key file must be acquired
  - the key file passphrase must be guessed

</td>
</tr>
<tr markdown="1">
<th scope=row>derived passphrases are unrecoverable if …</th>
<td markdown="block">

  - … the `derivepassphrase` configuration is lost or unrecoverable, or
  - … the master passphrase is forgotten

</td>
<td markdown="block">

  - … the `derivepassphrase` configuration is lost or unrecoverable, or
  - … the master SSH key file is lost, corrupted or otherwise unrecoverable, or
  - … the passphrase for the master SSH key is forgotten

</td>
</tr>
</tbody>
</table>

## Discussion

The master SSH key setup and the master passphrase setup differ somewhat in their setup complexity, setup brittleness, and resilience against loss of access and against attacks.
Usually, an aspect of the setup is both a strength for one of these criteria and a weakness for another one;
there is (in our opinion) no universally better choice.

Using a master SSH key instead of a master passphrase introduces an extra step during passphrase derivation:
the master SSH key first derives an "effective master passphrase", and this effective master passphrase is then used during the actual passphrase derivation.
In contrast, a master passphrase is used directly.

This extra step for the master SSH key setup implies a higher setup complexity:
an SSH agent (extra software) and the master SSH key file (extra essential files) are necessary, and the user must ensure continued access to the former and access and secrecy for the latter.
It also introduces additional failure modes:[^usual-failures] if the agent and/or the key file becomes unusable, then the user loses access to their derived passphrases as well.
This makes the master SSH key setup more brittle and less resilient against loss of access.

[^usual-failures]:
    The usual failure modes of `derivepassphrase` remain: the passphrase (master passphrase or the SSH key file passphrase) is forgotten, or the configuration is lost, corrupted, or otherwise unrecoverable.

By its nature, the master SSH key setup makes the master passphrase cryptographically infeasible to guess: guessing the master passphrase amounts to forging a cryptographic signature for the SSH key, which is infeasible by assumption.
The security of the setup then depends on the user's ability to secure the SSH key, e.g., by using a strong passphrase and brute-force-resistant settings for the SSH key file, and keeping it out of reach for attackers.
Similarly, a master passphrase must also be chosen carefully to be cryptographically infeasible to guess, and must be kept out of reach for attackers, e.g. by not writing it down anywhere.
Depending on the user, it may or may not be easier to secure a key file instead of memorizing a high-entropy passphrase.

We therefore have the following <b>recommendation</b>:
If you can count on having a working SSH setup on all machines you might want to access your derived passphrases on **and** if you already have SSH keys you must keep secure, then use a <b>master SSH key</b>.
Otherwise, use a <b>master passphrase</b>, e.g. by generating eight words from a Diceware list.
