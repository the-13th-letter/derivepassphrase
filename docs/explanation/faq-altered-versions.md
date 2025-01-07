# How to comply with the "altered versions" clause of the license

**Short answer:** change the package name and/or change the version number to include a [PEP 440][] "local version identifier".
If `derivepassphrase` ever rebrands, this applies to rebranded names too.
We try not to clash with anyone else, and will yank our offending releases if we do.

**Long answer:** We, upstream `derivepassphrase`, reserve the name `derivepassphrase` and certain version numbers for ourselves.
Specifically, our version numbers adhere to [PEP 440][] (or newer revisions) and generally do not include a "local version identifier".
To mark an altered version, we thus recommend that you change the software package name `derivepassphrase`, or use a version number with a local version identifier.
If we (upstream) decide to use a local version identifier, we will avoid all clashing local version identifiers we are aware of, and if informed of a clashing local version identifier after our release, will yank our offending version(s).

Should we (upstream) change the package name, we shall apply the same guidelines and checks concerning local version identifiers to the new package name.
A change of package name does *not* by itself imply permission to use the old package name for future releases of altered versions without marking them.

---

See also [the zlib project's take on how to mark altered versions][ZLIB_FAQ].
Like them, we recommend keeping our upstream Changelog (up to the point where you introduced modifications) and describing your modifications both there and in the README, in the appropriate level of detail.
We also request (but do not require) that you provide clear instructions in the README (and potentially other suitable places) on where and how to report problems that stem from your modifications, not from the upstream software package.

[PEP 440]: https://peps.python.org/pep-0440/
[ZLIB_FAQ]: https://github.com/madler/zlib/blob/v1.3.1/FAQ "see question #24"
