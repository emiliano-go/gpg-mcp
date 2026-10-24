# gpg-mcp

A security-focused [Model Context Protocol](https://modelcontextprotocol.io) server for GnuPG.

`gpg-mcp` lets an AI agent sign, verify, encrypt, decrypt and manage OpenPGP keys **without ever
receiving private key material**. Private keys stay in `gpg-agent`; passphrases go only into
`pinentry`; high-risk operations require an explicit human approval; destructive operations require
typing a fingerprint suffix.

> **Threat model in one sentence:** the MCP server is a policy boundary, not an OS sandbox. It
> prevents the agent from *receiving* private keys and from silently using them. For protection
> against an agent that already has shell access as the same OS user, run the signer as a separate
> user or use a hardware token (see [Stronger isolation](#stronger-isolation)).

---

## Why this exists

Most “GPG MCP” wrappers are thin `subprocess` shells: any tool with a `command: str` parameter, or
an agent that can ask for `--export-secret-keys`, defeats the point. `gpg-mcp` instead exposes a
fixed, typed surface with deliberate omissions:

- **No raw command execution.** There is no `run_gpg(args)` tool.
- **No secret-key export or backup.** `--export-secret-keys`, `--export-secret-subkeys` and
  `--export-secret-ssh-key` are unreachable.
- **No passphrase parameters.** No `--passphrase`, `--passphrase-fd`, `--passphrase-file`, no
  loopback pinentry, no passphrase in environment variables or stdin.
- **No `--homedir` override.** The keyring is fixed by configuration.
- **No short key IDs.** Operations require full 40- or 64-hex fingerprints.
- **No automatic key retrieval.** Verification does not silently fetch keys from the network.
- **No hidden recipients.** Decryption preflights the ciphertext and refuses messages not addressed
  to an allowed key.
- **A response guard.** If gpg ever emits something that looks like private key material, the call
  fails and the output is dropped.

---

## Security model

### What the server guarantees

1. **Private keys never cross the MCP boundary.** Listing secret keys returns metadata only.
   Signing and decryption are performed by `gpg-agent`.
2. **The server never sees a passphrase.** `--pinentry-mode ask` is forced; pinentry talks to the
   human directly. The server cannot read the passphrase from argv, env or stdin.
3. **Signing and decryption use allow-listed keys.** With a shared `~/.gnupg`, an empty allow-list
   denies both. With a dedicated keyring, the keyring itself is the allow-list boundary.
4. **Decryption is recipient-checked.** Before decrypting, `gpg --list-packets` is used to confirm
   the ciphertext is addressed to an allowed key. Hidden-recipient messages are refused by default.
5. **Invalid embedded signatures abort decryption.** If `verify=true` (default) and the decrypted
   message carries a bad, revoked or expired signature, the plaintext is **not** returned.
6. **High-risk operations require human approval.** A resolver asks the MCP client; if the client
   cannot ask, the operation fails closed.
7. **Destructive operations require typed confirmation.** Deleting or revoking a key requires the
   operator to type the last 8 characters of the fingerprint.
8. **Every high-risk operation is audited.** The ledger records fingerprints, payload SHA-256 and
   the decision — never plaintext or passphrases.
9. **No shell.** Commands are `execve`-style argv arrays. No shell interpolation, no option
   injection from user strings.
10. **Minimal environment.** `LD_*`, `GPG_AGENT_INFO`, `GPG_TTY`, `SSH_AUTH_SOCK` and other
    variables are not passed to gpg. Only the display/session variables pinentry needs are kept.
11. **Sanitised binaries and paths.** `gpg`, `gpgconf` and `zenity` are resolved to absolute paths,
    must be regular files, and must not be group/world writable.
12. **Bounded resources.** Input/output size caps, per-operation timeouts, a dedicated process
    group killed on timeout, and a 0700 temporary directory with 0600 files.

### What it does **not** guarantee

- **Same-user isolation.** Any process running as your OS user can read `~/.gnupg`, connect to the
  `gpg-agent` socket, or edit `~/.config/gpg-mcp/config.toml`. If the agent has shell access, the
  MCP policy is not an OS boundary. Use [stronger isolation](#stronger-isolation).
- **A malicious MCP client.** In `approval = "client"` mode, the client renders the approval
  dialog. A malicious client can fake it. Use `approval = "local"` (zenity/TTY, independent of the
  client) or a separate user/hardware token.
- **Compromised gpg or gpg-agent.** A compromised system binary can do anything. The binary checks
  reduce PATH hijacking, not supply-chain compromise.
- **Semantic safety.** The server can show *what* is being signed (hash and preview) but cannot
  judge whether the content is safe to sign. That judgement is the human's.

### Threat table

| Threat | Control |
|---|---|
| Agent asks for the private key | No tool returns it; response guard blocks accidental output |
| Agent tries `--export-secret-keys` | Option is never constructed; no raw exec |
| Agent supplies an option as a UID/fingerprint | Full-fingerprint validation; UIDs go into a parameter file, not argv |
| Agent signs a malicious tag/release silently | Allow-list + approval showing key, size, SHA-256 and preview |
| Agent decrypts stolen ciphertext | Allow-list + approval + recipient preflight |
| Agent encrypts secrets to an attacker key | Named recipients in approval + optional `allowed_recipients` |
| Agent imports a secret key | Secret packets detected and rejected |
| Agent deletes a key | `destructiveHint` + typed fingerprint suffix |
| Agent revokes a key | `destructiveHint` + typed fingerprint suffix |
| Agent reads plaintext from a bad signature | Bad/revoked/expired embedded signatures abort |
| Compression bomb / huge output | Capped streaming reads; process group killed |
| PATH hijack | Absolute binary paths, ownership/mode checks |
| Passphrase leak through argv/env/stdin | Pinentry only; no passphrase code path |
| Unattended prompt | Timeout kills the process group; no approval bypass |

---

## Architecture

```
MCP client (agent)
   │  stdio JSON-RPC
   ▼
gpg-mcp (Python, mcp SDK v2)
   │  fixed argv, stdin/stdout, --status-file
   ▼
gpg 2.4 ──► gpg-agent ──► pinentry (human passphrase)
   │
   ▼
GNUPGHOME (encrypted private keys + public keyring)
```

The server never opens private key files. It asks `gpg` to perform an operation; `gpg-agent`
unlocks the key only after pinentry succeeds.

---

## Quick start

Requirements: Python 3.11+, GnuPG 2.2+ (2.4 recommended), a pinentry program.

```bash
git clone https://github.com/emiliano-go/gpg-mcp.git
cd gpg-mcp
uv sync
uv run gpg-mcp init
```

`init` creates an **isolated** keyring at `~/.local/share/gpg-mcp/gnupg` (mode `0700`) and a config
at `~/.config/gpg-mcp/config.toml` (mode `0600`). It writes a conservative `gpg-agent.conf`:

```
default-cache-ttl 60
max-cache-ttl 300
ignore-cache-for-signing
no-allow-external-cache
no-allow-mark-trusted
pinentry-timeout 120
```

`ignore-cache-for-signing` means every signature asks pinentry again. Remove it only if you
understand the trade-off.

Check the installation:

```bash
uv run gpg-mcp doctor
```

Add it to your MCP client (example for a JSON `mcpServers` map):

```json
{
  "mcpServers": {
    "gpg": {
      "command": "gpg-mcp",
      "args": ["serve", "--config", "/home/you/.config/gpg-mcp/config.toml"]
    }
  }
}
```

Then, from the agent, create a key with `create_key` (the passphrase is entered into pinentry) and
use the returned fingerprint with `sign`, `encrypt` or `decrypt`.

> The dedicated keyring starts empty. `gpg-mcp` will not copy or export your existing secret keys.
> To reuse an existing key, move it yourself out-of-band, or keep using `~/.gnupg` with an explicit
> `allowed_sign_keys`/`allowed_decrypt_keys` allow-list.

---

## Configuration

Config path: `~/.config/gpg-mcp/config.toml`, or `--config`, or `GPG_MCP_CONFIG`.

| Key | Default | Meaning |
|---|---|---|
| `gnupg_home` | `~/.local/share/gpg-mcp/gnupg` | Isolated keyring. Must be `0700`. |
| `approval` | `client` | `client` (MCP elicitation), `local` (zenity/TTY), `none` (tests only) |
| `require_approval` | all high-risk ops | Operations that must be approved |
| `allowed_sign_keys` | `[]` | Full fingerprints allowed to sign. Empty = any in a dedicated keyring, none in `~/.gnupg` |
| `allowed_decrypt_keys` | `[]` | Same rule for decryption |
| `allowed_recipients` | `[]` | Optional recipient allow-list for encryption |
| `default_sign_key` | unset | Advisory default; explicit `signer` is still required |
| `enable_network` | `false` | Keyserver search/fetch/send |
| `enable_symmetric` | `false` | Symmetric encrypt/decrypt |
| `allow_unprotected_keys` | `false` | Permit `protect=false` key creation (test keyrings only) |
| `allow_hidden_recipients` | `false` | Permit decryption of hidden-recipient messages |
| `allow_secret_import` | `false` | Never enable in production |
| `max_input_bytes` | `10485760` | Input cap |
| `max_output_bytes` | `20971520` | Output cap |
| `timeout_s` | `120` | Per-operation timeout |
| `keygen_timeout_s` | `300` | Key generation / passphrase-change timeout |
| `keyserver` | `hkps://keys.openpgp.org` | Config-only; `hkps://` or `https://` only |
| `audit_log` | `~/.local/share/gpg-mcp/audit.jsonl` | Append-only JSONL, `0600` |

Environment overrides: `GPG_MCP_CONFIG`, `GPG_MCP_HOME`, `GPG_MCP_APPROVAL`,
`GPG_MCP_ENABLE_NETWORK`, `GPG_MCP_ENABLE_SYMMETRIC`, `GPG_MCP_AUDIT`.

---

## Tools

Read-only:

| Tool | Purpose |
|---|---|
| `list_keys` | List public keys or secret-key metadata (never secret material) |
| `get_key` | Full public metadata for one fingerprint |
| `export_public_key` | Armored/binary public key |
| `export_ssh_key` | OpenSSH public key for an authentication subkey |
| `inspect` | Inspect OpenPGP packets/keys without importing; rejects secret keys |
| `inspect_recipients` | Show recipients of a ciphertext without decrypting |
| `verify` | Verify detached, cleartext or inline signatures |
| `card_status` | OpenPGP smartcard status |
| `agent_info` | gpg version, sockets and agent cache options |
| `doctor` | Binary, keyring and policy health checks |

Crypto:

| Tool | Purpose |
|---|---|
| `sign` | Detached, cleartext or inline signature |
| `encrypt` | Encrypt to full recipient fingerprints |
| `sign_and_encrypt` | Sign and encrypt |
| `decrypt` | Decrypt with recipient preflight and signature check |
| `symmetric_encrypt` / `symmetric_decrypt` | Passphrase symmetric crypto (opt-in) |

Key management:

| Tool | Purpose |
|---|---|
| `create_key` | Create a key; passphrase via pinentry |
| `add_subkey`, `add_uid`, `set_expiry` | Modify a key |
| `change_passphrase` | Old/new passphrase via pinentry |
| `import_public_key` | Import public material; secret packets rejected |
| `delete_key` | Delete public or secret+public; typed confirmation |
| `set_ownertrust` | `never`/`marginal`/`full`; ultimate is CLI-only |
| `generate_revocation` | Return the stored revocation certificate |
| `import_revocation`, `revoke_key` | Apply a revocation; typed confirmation |

Network (opt-in):

| Tool | Purpose |
|---|---|
| `search_keyserver` | Search the configured keyserver |
| `fetch_key` | Fetch by full fingerprint |
| `send_key` | Publish a public key |

### Deliberately absent

- `export_secret_key` / secret-key backup.
- `run_gpg` / raw argv passthrough.
- Any passphrase parameter.
- `--homedir` from a tool.
- Arbitrary keyserver URLs per call.
- `--edit-key` interactive menu.
- `--trust-model` from user input.

---

## Approval modes

### `client` (default)

The server asks the MCP client to show an approval form. The form includes the operation, key
fingerprint, payload size, SHA-256 and a short preview. It is implemented as an MCP **resolver**, so
it works with both legacy and current protocol versions. If the client did not declare elicitation
support, the call fails closed.

### `local`

The server uses `zenity` (or fails closed when no display is available). This is independent of the
MCP client and is the better choice when you do not fully trust the client. Destructive operations
use a second `zenity --entry` prompt for the fingerprint suffix.

### `none`

For disposable test keyrings only. The audit ledger records `decision: skipped`.

---

## Keyring isolation

`gpg-mcp init` uses a dedicated keyring. That gives you:

- a separate `gpg-agent` cache from your everyday GnuPG use;
- a policy boundary where an empty allow-list means “this keyring only”;
- a safe place for test keys and agent-specific keys.

The dedicated keyring is not a security boundary against the same OS user. For that, see below.

---

## Stronger isolation

### Separate OS user (software)

Run the signer as a different user that owns the keyring, and expose only a narrow Unix socket to
the MCP server. The agent's user then cannot read the private keys or connect to the agent socket.
This is the strongest software-only design and is a natural next step; the current release keeps
the same-user model for simplicity.

### Hardware token (recommended for high-value keys)

Put the private key on an OpenPGP smartcard or YubiKey. The key never exists on disk, and each
signature can require a PIN and a physical touch. `gpg-mcp` works unchanged: `card_status` reports
the card, and `list_keys` marks card-backed secret keys. Key generation on the card is done
out-of-band with `gpg --edit-card`.

### systemd hardening

If you run the server as a service, at minimum:

```
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/gpg-mcp
RestrictAddressFamilies=AF_UNIX
```

and run it as a dedicated user in the separate-user design.

---

## Audit ledger

Every high-risk operation appends one JSON object to `audit.jsonl`:

```json
{"ts":"2026-10-24T20:00:00Z","event":"operation","tool":"sign",
 "fingerprint":"F759...E793","mode":"detached",
 "payload_sha256":"...","size":42,"result":"ok"}
```

The ledger contains no plaintext, no passphrases and no private key material. It is append-only with
mode `0600`, but it is not tamper-proof against the same OS user.

---

## Testing

```bash
uv run pytest            # never prompts; uses an ephemeral keyring
uv run ruff check .

# Optional: the two operations that intentionally need a human at pinentry
GPG_MCP_INTERACTIVE=1 uv run pytest tests/test_interactive.py -s
```

The default suite uses `pinentry-program /bin/false` in its throwaway keyring, so any unexpected
prompt fails the test instead of blocking. It creates an ephemeral keyring and runs real gpg
operations. It asserts, among other things, that:

- no response contains `PRIVATE KEY BLOCK`;
- no command line contains a forbidden option or a passphrase;
- secret-key imports are rejected;
- decryption refuses ciphertext addressed to another key;
- destructive operations require the typed fingerprint suffix;
- option-injection attempts fail validation.

---

## Limitations

- Text and base64 inputs are capped; large files should be handled out-of-band.
- Keyserver search output is human-readable text, not a structured list.
- Revocation uses the certificate generated at key creation time. If it is missing, generate one
  out-of-band with `gpg --gen-revoke`.
- Smartcard key generation and PIN management are intentionally out of scope.
- `approval = "client"` depends on the client rendering elicitation forms honestly.

---

## License

MIT. See [LICENSE](LICENSE).
