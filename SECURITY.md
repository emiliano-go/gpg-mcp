# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability. Report it privately through
GitHub's **Security → Advisories → Report a vulnerability** flow for
[emiliano-go/gpg-mcp](https://github.com/emiliano-go/gpg-mcp/security/advisories/new).

Include the affected version or commit, the operation sequence, and a minimal reproduction. I will
acknowledge receipt, investigate, and coordinate a fix and disclosure timeline.

## Supported versions

Security fixes are applied to the `main` branch and the latest release. Older releases are not
maintained separately unless a long-term support branch is announced.

## Threat model

`gpg-mcp` is a policy boundary around GnuPG, not an operating-system sandbox.

It protects against:

- an agent receiving private key material through any tool;
- an agent silently signing, decrypting, importing, or revoking without the configured human gate;
- an agent bypassing the allow-list, revoking a key through the generic importer, or hiding a bad
  signature behind a good one;
- an agent using an unrelated decryption key that happens to be present in the keyring;
- malformed or oversized GnuPG status/output causing a partial result to be treated as success;
- crafted UIDs or payload previews spoofing an approval dialog;
- an insecure audit file or configuration file being used silently.

It does **not** protect against:

- a process running as the same OS user, which can read `~/.gnupg`, talk to the gpg-agent socket,
  or edit the config file;
- a malicious MCP client that fakes approval in `approval = "client"` mode;
- a compromised `gpg`, `gpg-agent`, `pinentry`, or `zenity` binary;
- a human approving an operation whose content is malicious.

For stronger isolation, run the signer as a different OS user or use an OpenPGP smartcard/YubiKey.
The same-user limitation is intentional and documented in the README.

## Dangerous settings

- `approval = "none"` is a test mode. It is rejected at `serve` startup unless
  `allow_test_mode = true` (or `GPG_MCP_ALLOW_TEST_MODE=1`) and a dedicated `GNUPGHOME` are set.
- `destructive_confirmation = false` disables the typed fingerprint suffix for destructive
  operations. Do not use it with real keys.
- `enable_network = true` allows keyserver search, fetch/import, and publish operations.
- `enable_symmetric = true` enables passphrase-based symmetric crypto.

## Audit and failure behavior

`audit_required = true` (the default) makes a failed audit write fail the operation. Records are
phased: approval/intent before execution and outcome after. An outcome failure is reported explicitly
as "the operation may have completed" and is never retried. An existing audit file that is not a
regular file, is owned by another user, or cannot be tightened to `0600` causes the operation to
fail. Set `audit_required = false` only for disposable test keyrings.

The config is opened with `O_NOFOLLOW` and validated through `fstat`; its parent must be a user-owned
directory that is not group/world-writable. Symmetric decryption is restricted to symmetric-only
ciphertext so hybrid messages cannot bypass the public-key allow-list.

## Platform support

The implementation relies on Unix permissions, `os.getuid`, POSIX process groups, and `zenity`.
Supported platforms are Linux and other Unix-like systems with GnuPG 2.2+ (2.4 recommended).
Windows is not supported.
