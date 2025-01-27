---
title: What are "interchangable passphrases" in `vault`, and what does that mean in practice?
---

# What are "interchangable passphrases" in `vault`, and what does that mean in practice?

## What are "interchangable passphrases"?

The "vault" derivation scheme internally uses PBKDF2-HMAC-SHA1[^1] to turn
the master passphrase[^2] into a pseudo-random bit sequence, which then
drives the actual passphrase derivation.
In this context, the master passphrase is passed directly as a key to
HMAC-SHA1, and because HMAC-SHA1 requires keys of exactly 64 bytes size, the
key is thus subject to the HMAC key mapping procedure.
Because the mapping of infinitely many arbitrarily sized keys to 64-byte
sized keys cannot be one-to-one, there exist pairs of keys that behave
identically when passed into (PBKDF2-)HMAC-SHA1, i.e., the keys (master
passphrases) are "interchangable" from the vault scheme's perspective.

Fundamentally, this is an issue of *encoding*: the master passphrase is
interpreted as an encoding of the HMAC-SHA1 key, and this encoding is not
unique, so the effective space of HMAC-SHA1 keys is reduced through the
presence of "non-canonical" encodings of keys.

  [^1]: PBKDF2 is a key derivation function, published in [RFC 2898][].
  It uses a pseudo-random function such as HMAC-SHA1 (hashed message
  authentication code, specified in [RFC 2104][] and using SHA1 as the
  underlying hash function) when processing its input.  PBKDF2 passes the
  key on to its pseudo-random function, and otherwise only depends on the
  output of the pseudo-random function, not on the key.

  [^2]: If you use a master SSH key, it is first converted to an "equivalent
  master passphrase".

  [RFC 2104]: https://datatracker.ietf.org/doc/html/rfc2104
  [RFC 2898]: https://datatracker.ietf.org/doc/html/rfc2898

## What is the HMAC key mapping procedure?

???+ abstract "HMAC key mapping procedure"

    Let <var>MP</var> denote the master passphrase, and let <var>K</var>
    denote the HMAC key candidate.  Let <var>B</var> denote the block size
    of HMAC-SHA1 in bytes, i.e., `64`.  At the beginning,
    <var>K</var> = <var>MP</var>.

    1.  If <var>K</var> (= <var>MP</var>) is larger than <var>B</var>, set
        <var>K</var> to `SHA1(K)`.  This updates <var>K</var> for all
        further steps below.
    2.  If <var>K</var> is smaller than <var>B</var>, append as many NUL
        bytes as necessary to extend <var>K</var> to size <var>B</var>.
    3.  Use <var>K</var> as the HMAC key.

## What effect does the HMAC key mapping procedure have on key security?

The key space shrinks to 99.6% of its original size.
But since it started out as astronomically large (2^512^), it *still* is
astronomically large.

??? example "Mathematical details: key space"

    | variant                      | key space size | fraction of total size |
    |:-----------------------------|:---------------|:-----------------------|
    | 64-byte keys only            | 256^64^ = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084096 | 99.609375% |
    | full key size up to 64 bytes | (256^65^ – 1) / (256 – 1) = 13460387568883548460748825096238025916214579019888834136067575410167731732152266768867764001296969715641757473316629133406121545097483615318772604492382465 | 100% |

    The key space sizes can be calculated using the following formulas.  Let
    <var>q</var> = `256` denote the alphabet size of binary strings, and let
    <var>n</var> denote the string length.  The total count of all strings
    of size <var>n</var> is <var>q</var>^<var>n</var>^, and the total count
    of all strings up to (and including) size <var>n</var> is
    (<var>q</var><sup><var>n</var> + 1</sup> – 1) / (<var>q</var> – 1) per
    the formula for geometric series.

    Verification:

    ~~~~ shell-session
    $ # using GNU bc 1.07.1
    $ 
    $ BC_LINE_LENGTH=0 bc <<'HERE'
    > # The total count of size 64 byte strings.
    > 256^64
    > # The total count of byte strings of size 64 or less.
    > (256^65 - 1) / (256 - 1)
    > # The fraction of the former within the latter.
    > scale = 8
    > (256^64) / ((256^65 - 1) / (256 - 1))
    > HERE
    13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084096
    13460387568883548460748825096238025916214579019888834136067575410167731732152266768867764001296969715641757473316629133406121545097483615318772604492382465
    .99609375
    $ 
    $ BC_LINE_LENGTH=0 bc <<'HERE'
    > # The fraction of unusable keys.
    > scale = 160
    > (256^64 - 1) / (256^65 - 1)
    > 1 / 256
    > HERE
    .0039062499999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999997097
    .0039062500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
    ~~~~

In particular, assuming a sufficiently secure master passphrase, this
mapping procedure is still cryptographically secure against attackers
without possession of the master passphrase if the hashing function (here:
SHA1) is secure against preimage attacks:

  * The attacker can attempt to guess a NUL-extended version of the
    passphrase if it is shorter than or equal in length to 64 bytes.  This
    has the same computational cost as guessing the master passphrase
    directly, which is cryptographically secure by assumption.

  * The attacker can attempt to guess a hashed and NUL-extended version of
    the passphrase if it is larger than 64 bytes.  This amounts to carrying
    out a preimage attack against the SHA1 digest of the master passphrase,
    which is also cryptographically secure by assumption.

## What effect does the HMAC key mapping procedure have on `derivepassphrase`?

`derivepassphrase vault` does not check for interchangable passphrases, and
will happily accept any (non-empty) passphrase it is given.
The [`derivepassphrase.vault.Vault`][] class does not check for
interchangable passphrases either, and will happily accept any passphrase it
is given, even empty ones.

Most interchangable variations of a master passphrase contain binary
characters such as NUL, or even arbitrary byte sequences, which may be hard
to type in or impossible to express in certain storage formats.  As such, it
is unlikely---but otherwise supported---that the user would want to enter
or store a different, interchangable version of their master passphrase in
the first place.
