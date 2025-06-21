# `derivepassphrase` wish other-derivation-schemes

???+ wish "Wish details: Consider implementing passphrase schemes other than vault&apos;s"
    <table id="bug-summary" markdown>
        <tr><th scope=col>Class<td><i>wish</i><td>This is a request for an enhancement.
        <tr><th scope=col>Priority<td><i>medium</i><td>This should be fixed one day.
        <tr><th scope=col>Difficulty<td><i>tricky</i><td>Needs many tuits.
        <tr><th scope=col>Present-in<td colspan=2>0.1.0 0.1.1 <b>0.1.2</b> 0.1.3 0.2.0 0.3.0 0.3.1 0.3.2 0.3.3 0.4.0 0.5
        <tr><th scope=col>Depends<td colspan=2>[scheme-specific-cli-and-config](scheme-specific-cli-and-config.md){: .fixed }
    </table>

Consider implementing other deterministic password/passphrase generation schemes, beyond vault.

Some candidates:

- ??? failure "[`chriszarate/supergenpass`](https://github.com/chriszarate/supergenpass)"

        - [standalone library](https://github.com/chriszarate/supergenpass-lib)
        - High-level scheme: hash the master passphrase and the domain/URL repeatedly until the output satisfies a certain passphrase pattern.
            - The hash is either MD5 or SHA512.
            - The hash input is the naive concatenation of master passphrase, an optional secret string, a colon, and the domain/URL.
            (No protection against components aliasing each other.)
            - The output is base64-encoded and truncated to at most 24 characters.
            - The output pattern is static, and forces the output to start with a lowercase character and contain both an uppercase character and a number.
            - The hash is used for at least 10 rounds, more if necessary to satisfy the output pattern.
            - There is no explicit support for deriving a different passphrase for a certain domain/URL if the current one was compromised; this needs to be effected by changing the hash, the hash rounds, the master passphrase or the optional secret.
            - The domain usually is truncated to the "base domain" just below the TLD, using a static list of TLDs.
        - do not implement
        - improvised key derivation function does not appear to be cryptographically sound
        - design also contains certain unfortunate choices (idiosyncratic domain truncation, fixed pattern and fixed character set for the derived passphrase, low maximum derived passphrase length) which harm the usability of this system
        - offers less flexibility and less cryptographic soundness than the `vault` scheme does, but has no other redeeming qualities instead

- ??? failure "[`grempe/strongpass`](https://github.com/grempe/strongpass)"

        - High-level scheme: pass the master passphrase and the service name to a cryptographic key derivation function, then convert the output to a suitable passphrase.
            - A master key is generated from the master passphrase and the service name, via HMAC-SHA512.
            - A salt is generated from the service name and other, user-controlled input, hashed with SHA512.
            - The derived key is derived from the master key using scrypt with the aforementioned salt.
            - The derived key is converted to base64. The first 18 characters are used directly, the last two characters are converted to a number and a symbol, respectively. This yields a 20-character passphrase with a guaranteed number and symbol at the end.
        - do not implement
        - very sound design that at its core is not unlike the `vault` scheme, but lacks any configurability for the output (length, character set, reset counter)

- ??? failure "[`aprico-org/aprico-gen`](https://github.com/aprico-org/aprico-gen)"

        - High-level scheme: the input is put into a cryptographic key derivation function, then the result is rehashed until it satisfies a certain passphrase pattern.
            - uses scrypt for KDF and for rehashing (with lower CPU cost factor)
            - output passphrase pattern is static, but the character classes (alpha, number, symbol) can be enabled and disabled
        - do not implement
        - sound design, but lacks configurability for the output

- ??? note "[Master Password/Spectre.app scheme](https://spectre.app/blog/2018-01-06-algorithm/)"

        - High-level scheme: the input is put into a cryptographic key derivation function, then the result is used as a pseudorandom stream of bits to select an output template and characters in that template.
            - uses scrypt for KDF
            - uses a separate reset counter
            - provides only a limited set of output templates
            - strives for maximum statelessness: by design, it should be possible to try out all sensible counter values and templates without getting blocked for excessive password attempts
            - published specification (with minor errors and omissions)
            - test suite
            - several "old" versions of the algorithm contain implementation mistakes relative to what the spec describes
        - **implement**
        - …but use "master" terminology freely
        - sound design, and battle-tested
        - very pure application of the statelessness principle without sacrificing too much practicability

- ??? question "[LessPass](https://github.com/lesspass/lesspass/)"

        - High-level scheme: same as Master Password/Spectre.app
            - uses PBKDF2-HMAC-SHA256 as KDF
            - character sets can be turned on and off
            - "old" versions of the algorithm
            - test suite
            - supports "profiles" (akin to `vault` service settings) for customizing character sets, length, counter values, etc.; the author advises using only public site-specific profiles, not user-specific ones
            - web client uses "visual fingerprinting" to guard against data entry mistakes… but this allows online attacks against the master passphrase
        - undecided
        - definitely do not implement visual fingerprinting

- ??? note "[Diceware](https://theworld.com/~reinhold/diceware.html)"

        - High-level scheme: generates passphrases from a random bitstring via a table of words, to be concatenated.
            - not a full passphrase derivation scheme (lacks a hashing or key-derivation step), but combinable with other "classic" passphrase derivation schemes
            - original wordlist by Arnold G. Reinhold; other wordlists available, e.g. from the EFF
        - **implement**, as a supplement to existing passphrase derivation schemes
        - requires a new API in the other derivation schemes to expose the pseudo-random bitstream from which the final passphrase normally is assembled

The hard part about these will probably not be the coding, but the correctness testing.
