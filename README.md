# sec

A local secrets manager for projects, built for **agent-safe workflows**
(Claude Code and friends): secret values never appear on argv, in shell
history, or in an agent's chat transcript. Input is hidden / from stdin /
from the clipboard; consumption is env injection (`run`) or writing to a
file (`export`).

The store is a local SQLite database whose catalog and every value are
encrypted separately with XChaCha20-Poly1305 before they reach the database; the
master key lives separately (macOS Keychain / Secret Service on Linux /
Credential Manager on Windows / env / file), and portable backups are
passphrase-protected via Argon2id (details in
[Cryptography](#cryptography)). This is a tool that works **locally on your
device** — not a service and not part of CI: secrets never leave the
machine. The one exception is `sec share` (handing a secret over via a
one-time link): only **ciphertext** leaves the machine, and the decryption
key is generated locally and lives in the URL fragment, which is never sent
to the server.

## Installation

**CLI** (the `sec` binary) via Homebrew — no Go required:

```sh
brew install kaidstor/tap/sec
sec version
```

Via **Nix** (flakes):

```sh
nix profile install github:kaidstor/sec
```

**Agent skill** (instructions for Claude Code, Codex, and other coding
agents) is embedded in the binary and unpacks itself on macOS during
`brew install`/`upgrade`. Manually — one command (`sec skills status` shows
what is installed):

```sh
sec skills install
```

Installed skill copies are stamped and then update automatically on every
`sec` run — the skill version always matches the CLI version. A binary-free
alternative is `npx skills add kaidstor/sec` via
[skills.sh](https://skills.sh) (installs `SKILL.md` only and updates only by
hand); self-update leaves those installations alone.

**Windows**: a prebuilt `sec.exe` ships in a zip archive on
[GitHub Releases](https://github.com/kaidstor/sec/releases)
(`sec_<version>_windows_amd64.zip` or `arm64`); unpack it into a directory
on `PATH`. The master key is kept in Credential Manager, the store lives at
`%LOCALAPPDATA%\sec\store.enc`, the key file (fallback) at
`%APPDATA%\sec\key`.

## Quick start

```sh
# inside a project directory: start the dev server with its secrets
sec run -- just dev

# save a secret without ever seeing the value (user copied it to the clipboard)
sec set whois/API_TOKEN --clipboard --clear

# pull an existing .env or JSON into the store
sec import whois path/to/.env
cat creds.json | sec import whois

# safely show command output that might contain a secret
just dev 2>&1 | sec redact       # values → [redacted:proj/KEY], unknown BOT_TOKEN=… → [redacted:field]

# before committing, check that no secret leaked into the index
sec scan --staged
```

## What it does

- **Leak-free input** — `set` (hidden input / stdin / clipboard / a file via
  `--from-file`, including binary certificates and keys), `gen` (generate a
  password/token without ever displaying it).
- **Consumption without disclosure** — `run` (env injection into the
  process), `export` / `render` (to a 0600 file), `get --out` (file secrets
  back onto disk with their original name and permissions), `otp`
  (TOTP/HOTP codes from a stored seed). `--file`/`--out`
  (export/render/get) also accept an scp-style `host:/path` — writing
  straight to a remote host over ssh stdin.
- **File secrets** — a certificate/key/keystore lives in the store, not on
  disk: `run --file KEY -- cmd` materializes it into a temporary 0600 file
  for the command's lifetime and hands the path over in an env variable
  (the systemd `LoadCredential` pattern); `kind: file` keys stay out of
  `run`/`export` env injection by default (`--include-files` brings them
  back). What goes into the variable, when the `--file ENV=KEY` form is
  useful, and why `scan` is noisy about imported config — see
  [`docs/file-secrets-and-scan.md`](docs/file-secrets-and-scan.md) (in Russian).
- **Comparison without disclosure** — `peek` / `fingerprint` / `verify` /
  `diff` (fingerprints that are safe to paste into a chat).
- **Configs on remote hosts** — `diff <proj> <host>:/app/.env` shows how the
  store diverged from a production config (read-only, values are never
  revealed), and `deploy --to <host>:/app/.env` applies the store as a
  **merge**: it updates its own keys and leaves foreign keys, line order,
  and comments untouched. Plus `--sudo` for root-owned configs, a backup on
  the host, post-write fingerprint verification, and `--after` to restart
  the service — details in [`docs/deploy.md`](docs/deploy.md) (in Russian).
- **Search** — `find <pattern>` (across the whole store → `proj/KEY`) and
  `ls --filter` (narrow one listing): substring or glob, so you never have
  to page through the store.
- **History and rotation** — `history`, `undo`/`redo`, `forget`, rotation
  metadata (`meta`, `stale`), store health (`doctor`).
- **Leak protection** — `scan` (find stored values in files / a git diff)
  and `redact` (scrub them out of arbitrary text; on top of stored values it
  hides fields named like `*_TOKEN`/`*_PASSWORD`, passwords in URIs and PEM
  private keys — a heuristic, not a DLP guarantee). Values
  marked `--kind config` (an endpoint, a cache size, a provider list) are
  not secrets: `scan`/`redact` skip them (`--include-config` brings them
  back) and `diff`/`deploy` show them in plain text.
- **Shared values** — `link` / `extend` (links and pack inheritance: one
  source of truth instead of copies); `set`/`gen`/`import` notice on their
  own that a value already exists under another address and suggest a
  ready-to-paste `sec link` (all accumulated duplicates — `doctor`).
- **Profiles** — `proj@profile` (like `pkg@version` in npm): several value
  sets for the same keys (companies, stages) under one service —
  `sec run bot@max -- …`; the default profile is declared in `.sec`.
- **Sharing via link** — `share`: a one-time link (or with a TTL up to
  7 days) to a secret, a value from stdin, a file, or a whole pack —
  `sec share <proj> --all` (or `--only A,B`): the recipient sees the key
  list, copies values one by one or downloads a ready `.env`; file keys
  come as separate files. Encrypted locally (AES-256-GCM), the server
  stores ciphertext only; the key lives in the URL fragment and decryption
  happens in the recipient's browser. Self-hosted server —
  [`server/`](server/); point the CLI at yours with
  `sec share setup <url>` and a server-issued token. How it works inside —
  [`docs/share.md`](docs/share.md) (in Russian).
- **Migration and sync** — `backup` / `restore` / `sync` (a portable
  passphrase-protected blob), `rekey` (master key rotation), a bridge to
  **Infisical**.
- **What you actually use** — `sec stats`: a local counter of command and
  flag invocations by day, and most importantly a list of what exists but
  has never been used. Names of commands and flags only, no values, fully
  on-machine (disable with `SEC_NO_USAGE=1`).
- **Shell completion** — `sec completion zsh|bash|fish`: dynamic completion
  of projects, keys (`proj/<TAB>`), and profiles (`proj@<TAB>`) in the
  terminal (a convenience for humans; agents call `sec` non-interactively).
- **Desktop app** — [`app/`](app/): a Tauri client on top of the CLI
  (search, copy via `--clip`, history, sharing a key or a pack, themes).
  Install: `brew install --cask kaidstor/tap/sec-app` (the CLI comes along
  as a dependency). There is also a Raycast extension —
  [`raycast/`](raycast/).

The full command reference lives in [`cli/README.md`](cli/README.md)
(currently in Russian).

## Raycast

[`raycast/`](raycast/README.md) contains a local Raycast extension (a UI
for humans): search across projects/keys, copying values and TOTP codes to
the clipboard, adding, editing, and generating secrets. Values never pass
through the extension — the CLI fills the clipboard itself (`--clip`); the
UI only ever shows masks, fingerprints, and metadata.

```sh
cd raycast && npm install && npm run dev   # imports into Raycast, survives Ctrl+C
```

## For agents

The safety rules (what may be printed to a chat, how to create and consume
secrets, how to scrub output) live in [`SKILL.md`](SKILL.md) (in Russian) —
the contract a coding agent follows.

## Cryptography

Standard primitives only: `crypto/*` from the Go stdlib and
[`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) (argon2,
chacha20poly1305) — vendored into the repository; there is no homegrown
cryptography.

| What | Algorithm | Parameters |
| --- | --- | --- |
| Store catalog and values | **XChaCha20-Poly1305** (AEAD) | 256-bit key, 192-bit nonce (random per blob), 128-bit tag |
| Master key | `crypto/rand` (OS CSPRNG) | 32 bytes, stored as hex64 |
| Passphrase backup / sync | **Argon2id** → XChaCha20-Poly1305 | 64 MiB, t=3, p=4, 16-byte salt, 32-byte key |
| Fingerprints (`fingerprint`, `diff`, `peek`) | **HMAC-SHA-256** under the master key | truncated to 64 bits |
| Value generation (`gen`) | `crypto/rand` | uniform character choice (`rand.Int`, no modulo bias) |
| TOTP / HOTP (`otp`) | **HMAC-SHA-1 / SHA-256 / SHA-512** | RFC 6238 / RFC 4226; algorithm/digits/period/counter from the `otpauth://` URI |

### The store

The store is a local SQLite database (`modernc.org/sqlite`, pure Go, no CGO,
no server). Encryption happens in sec itself, before anything reaches the
driver:

```
sec_meta     store_id — random store UUID (plain)
sec_catalog  one blob: nonce(24) │ XChaCha20-Poly1305(catalog)
sec_payload  one row per value version: id (random) │ nonce(24) │ XChaCha20-Poly1305(value)
```

The catalog holds project and key names, links, inheritance, metadata
(notes, file names), timestamps, value ids and their summaries (length,
HMAC). Every value (current, history, redo) is its own blob with its own
nonce. The AAD binds a blob to the format, the store and its role
(`SECSTOR3\0catalog\0<store_id>`, `SECSTOR3\0payload\0<store_id>\0<id>`), so values
cannot be swapped between rows or stores, and a decrypted value is also
checked against the length and HMAC in the catalog. Value ids are random and
immutable: a new value is always a new row; unreferenced rows are deleted in
the same transaction.

Why: `get`, `ls`, `find` and completion read the catalog and at most one
value, so their cost no longer grows with the size of unrelated file secrets
(the old format decrypted and parsed the whole store on every call — ~2.5 s
on a 447 MiB store). `run --only` and skipping file secrets are decided from
the catalog before any value is decrypted. Reads are a SQLite snapshot;
writes take `flock` on `store.enc.lock` and `BEGIN IMMEDIATE` before reading
the catalog — no lost updates, bounded waits (10 s lock, 5 s busy) ending in
a clear error. WAL with `synchronous=FULL`; the snapshot is closed before
`exec`, child processes and network calls.

**Visible without the key:** structure — the number of values and each
one's size, the catalog size, file mtimes. Not visible: names, metadata,
values, which value belongs to which key. A deleted version is removed
logically; physical erasure on SSDs, filesystem snapshots and backups is not
promised.

**Copying the database file by hand** is only safe together with
`store.enc-wal` and `store.enc-shm` and not during a write. To move a store,
use `sec backup` / `sync`.

**The old SECSTOR2 format** — the whole JSON in one AEAD blob
(`"SECSTOR2" │ nonce(24) │ XChaCha20-Poly1305(JSON)`, magic in the AAD) —
is still read unchanged. `sec migrate` converts it under the same lock old
binaries take: the database is built alongside, re-read and compared with
the original model byte for byte, the old file is kept as
`store.enc.v2-<time>.bak`, and one `rename` puts the database in place — a
crash at any step leaves either the old store or the complete new one.
`sec migrate --to-v2` goes back, including everything written after the
switch. An old sec refuses a SQLite store ("не похоже на хранилище sec") and
creates nothing. New stores are created as SQLite.

### The master key

32 random bytes from the OS CSPRNG, created on the first `set`/`import`.
Looked up in order: env `SEC_KEY` → the OS secret store (macOS Keychain,
Secret Service via `secret-tool` on Linux, Credential Manager via advapi32
on Windows) → the file `~/.config/sec/key` (0600; `%APPDATA%\sec\key` on
Windows). The key is handed to the OS store via the utility's stdin or a
native syscall — it never shows up in `ps`/argv. The key is **not** derived
from a user password: decryption is non-interactive, which is why `sec run`
works in scripts without a prompt.

`sec rekey` generates a new key and re-encrypts the store. The key backend
and the store cannot be written in one transaction, so the new key first goes
to a separate slot (Keychain `master-next`, file `key.next`, for `SEC_KEY` the
file `store.enc.rekey-key`), then the store is re-encrypted in one commit,
then the key becomes primary and the slot is cleared. A crash in between
leaves the store readable: sec tries the slot key when the primary one does
not fit, and the next write finishes the rotation. Details:
[`cli/README.md`](cli/README.md#ротация-мастер-ключа).

### Backup, restore, and sync

`backup` / `restore` / `sync` produce a portable blob — the complete,
self-contained JSON of the previous schema (version 2) with every value and
no references to local database rows; a missing value is a refusal, never a
partial backup. The blob is independent of the master key: its key is derived from a passphrase via **Argon2id**
(memory-hard, resistant to GPU/ASIC brute force).

```
"SECBAK03" │ mem(4) │ time(4) │ par(1) │ salt(16) │ nonce(24) │ XChaCha20-Poly1305(store JSON)
└──────────────── AAD: the whole header up to the nonce ────────────────┘
```

The Argon2id parameters (64 MiB / t=3 / p=4 — above the OWASP minimums) are
stored **in the file itself**, so they can be raised later without breaking
existing blobs; on read they are validated against sane bounds so that a
corrupt or hostile header cannot make Argon2 eat all available memory. Blob
strength = passphrase strength: for a file in Dropbox/iCloud, use a long
passphrase.

It also follows that mac↔Linux↔Windows machines sync without ever moving
the master key, and an old backup still opens with its passphrase after a
`rekey`.

### Fingerprints and comparison

A `fingerprint` is the HMAC-SHA-256 of a value **under the master key**,
truncated to 8 bytes (`fp:…`). The keying is the point: a short or
dictionary value cannot be brute-forced from its fingerprint without the
master key, which makes `fp:` safe to show in an agent chat, a ticket, or a
screenshot. The flip side: fingerprints are only comparable between stores
under the same key (your own synced machines), not against someone else's
store. Value and fingerprint comparisons run in constant time
(`crypto/subtle`, `hmac.Equal`).

### Value generation

`sec gen` draws characters from `crypto/rand` via `rand.Int` (uniform, no
modulo bias). The default alphabet is 62 characters (A–Z a–z 0–9), 84 with
`--symbols`. At the default length of 32 that is ≈190 bits of entropy
(≈204 bits with `--symbols`). The value goes straight into the store and is
never printed — creating a password without knowing it is a first-class
scenario.

### What cryptography does **not** cover

- **The access log** `audit.jsonl` is plain JSONL next to the store: it
  records only operation names and key addresses (`proj/KEY`), never
  values.
- **`export` / `render`** write a plaintext `.env` to disk (0600) — a
  deliberate exit from the encrypted world; do not commit such a file.
  Where possible, prefer `sec run` (env injection into the process, no
  file ever exists).
- **Process memory** — the decrypted store and the master key live in the
  Go heap in plain text; there is no reliable wiping (`mlock`/zeroize), so
  this does not protect against a memory dump or local malware.
- **The Infisical bridge** — encryption happens on Infisical's side; `sec`
  only ferries values through their CLI (stdout / a temporary 0600 file),
  never through argv.

## Security

Protects against **accidental leakage** of secrets into agent chats, shell
history, screenshots, and logs. Does not protect against local root /
malware (as with any manager that decrypts on the same machine) — a
deliberate trade-off in exchange for convenient non-interactive operation.
More in the "Threat model" section of
[`cli/README.md`](cli/README.md#модель-угроз).

## License

[MIT](LICENSE).

---

🇷🇺 Этот документ по-русски: [README.ru.md](README.ru.md).
