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

The config path is walked with directory file descriptors and `O_NOFOLLOW`, and the opened file is
validated through `fstat`; ancestors must be owned by the user or root and must not be group/world
writable without the sticky bit. The keyring path is not symlink-resolved; `serve`, `doctor` and
`init` validate the original path and its full ancestor chain, rejecting symlinked keyrings or
ancestors. `init` creates the config with exclusive/no-follow semantics, refuses a symlinked
`gpg-agent.conf`, and cannot write through a dangling config symlink. Config, keyring and audit
directories are created incrementally relative to validated directory descriptors; a symlinked or
otherwise unsafe ancestor is rejected before anything is created through it. The audit ledger uses
the same directory-fd walk, so an unsafe ancestor cannot redirect or replace it. Secure-walk
failures close every opened descriptor, so repeated invalid paths do not leak file descriptors.

Symmetric decryption is restricted to symmetric-only ciphertext and applies the same strict status
policy: `DECRYPTION_OKAY` is required, generic errors/failures and bad integrity checks are fatal,
and an unexplained nonzero exit is rejected. With `verify=false`, only an explicitly recognized
embedded-signature failure may explain a nonzero exit. `decrypt` rejects symmetric-only ciphertext
and, for hybrid ciphertext, requires GnuPG to report an actual allow-listed public key; it never
falls back to the symmetric route. Only the recoverable symmetric-passphrase failure is
tolerated for hybrid input, and only alongside a successful public-key decryption. Generic errors,
failures, and unexplained nonzero exit codes are fatal. A custom policy that gates only
`symmetric_decrypt` therefore cannot be bypassed through `decrypt`.

## Platform support

The implementation relies on Unix permissions, `os.getuid`, POSIX process groups, and `zenity`.
Supported platforms are Linux and other Unix-like systems with GnuPG 2.2+ (2.4 recommended).
Windows is not supported.
