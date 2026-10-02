# pigeon

A keyboard-driven terminal email client, written in Rust, with **no C anywhere in
the dependency tree** and **encryption at rest by default**.

```
┌ folders ────┐┌ messages · 248 · date ↓ ──────────────────────────────────────┐
│ ▸ INBOX  12 ││   12:04  Ada Lovelace          Re: analytical engine notes  ★ │
│ ↗ Sent      ││   11:51  build@ci.example      nightly #4412 passed        @  │
│ ✎ Drafts    ││ ▾ 09:30  Grace Hopper          Re: compiler design         (4)│
│ ⌸ Archive   ││     09:31  Alan Turing           └ Re: compiler design      🔒 │
│ ␡ Trash     ││   Yesterday  Katherine Johnson  trajectory review             │
└─────────────┘└──────────────────────────────────────────────────────────────┘
┌ message ─────────────────────────────────────────────────────────────────────┐
│ From     Grace Hopper <grace@example.org>                                    │
│ Subject  Re: compiler design                                                 │
│ [signed] [3 remote images blocked — I to allow]                              │
│ ──────────────────────────────────────────────────────────────────────────── │
│ The compiler should read the whole program before it emits anything…         │
└──────────────────────────────────────────────────────────────────────────────┘
 idle │ 248/248 │ threads · text │ ? help
```

## Why the dependency rules matter

Two constraints shaped every dependency choice:

**Pure Rust.** No `cc`, `cmake`, `pkg-config`, `openssl-sys`, `libsqlite3-sys`,
`ring`, or `aws-lc-rs`. `cargo build` needs no C toolchain, cross-compiles
cleanly, and has no C memory-safety surface in the parsing or crypto paths —
which is exactly where hostile input arrives in a mail client.

| Job | Usual choice | What pigeon uses | Why |
|---|---|---|---|
| Storage | SQLite / SQLCipher | [`redb`](https://crates.io/crates/redb) | SQLite is C; SQLCipher is C + OpenSSL |
| TLS | rustls + `ring`/`aws-lc-rs` | rustls + [`rustls-graviola`](https://crates.io/crates/rustls-graviola) | the usual providers ship C and assembly |
| OpenPGP | `gpg(1)` subprocess | [`rpgp`](https://crates.io/crates/pgp) | no external binary, no GnuPG IPC |
| SMTP | `lettre` / `mail-send` | hand-written (`src/net/smtp.rs`) | both pin a non-pure TLS provider |
| HTTP (OAuth2) | `reqwest` | hand-written (`src/net/http.rs`) | same reason; only needs POST + JSON |
| Primitives | OpenSSL | RustCrypto (`chacha20poly1305`, `argon2`, `sha2`, `hmac`, `hkdf`) | pure Rust, audited, maintained |

Verify the rule holds:

```sh
for c in cc pkg-config cmake ring openssl-sys libsqlite3-sys libz-sys bzip2-sys; do
    cargo tree -i "$c" -e normal,build
done
```

All eight come back empty. (`zlib-rs` and `libbz2-rs-sys` do appear — they are
pure-Rust reimplementations, not bindings.)

**Encryption at rest.** Described below.

## Security model

### At rest

- A 32-byte master key is generated once and wrapped with a key-encryption key
  derived from your passphrase via **Argon2id** (256 MiB, 3 passes, 4 lanes).
  The wrapped key lives in `vault.key`, mode `0600`.
- Every subsystem derives its own key from the master via **HKDF-SHA256**, so
  compromising one does not yield the others.
- Every database value is sealed with **XChaCha20-Poly1305** under a random
  192-bit nonce. The AAD binds each record to its table and key, so a record
  cannot be moved or replayed elsewhere in the file without detection.
- Folder and account names are not stored in database keys; keys carry an
  HMAC-derived scope prefix instead. UIDs stay in the clear so that per-folder
  range scans remain possible — message *counts* are therefore observable, but
  names and contents are not.
- The full-text index is a **blind index**: terms are stored as
  `HMAC-SHA256(index_key, field ‖ term)`, truncated to 16 bytes. Someone holding
  the database file cannot enumerate your vocabulary. The trade-off is that only
  whole-token equality is answered from the index; prefix and substring queries
  fall back to decrypt-and-scan.
- OAuth refresh tokens are stored in the encrypted database, not the OS keyring,
  so they are protected by the same key as the mail they unlock.

`tests/encryption_at_rest.rs` asserts these properties by writing a known
message and then scanning the raw database file for the plaintext.

### End to end

OpenPGP via `rpgp`: sign, verify, encrypt, and decrypt, with the RFC 3156
`multipart/signed` and `multipart/encrypted` layouts and inline PGP recognised on
receipt. Keys live under `<data-dir>/keys`; secret key files are written `0600`.

Set `encrypt_policy = "always"` on an account to refuse to send a message when a
recipient key is missing, rather than silently falling back to cleartext.

### While reading

Mail is hostile input, so the viewer:

- never fetches remote content — loading a remote image confirms your address to
  the sender. `I` allows it per message, and the banner says how many were blocked;
- strips 1×1 tracking pixels entirely rather than rendering empty boxes;
- drops `<script>` and `<style>` before rendering;
- writes attachments to a per-process `0700` directory, never a shared `/tmp` path;
- keeps `Bcc` out of the message body — those addresses go in the SMTP envelope only;
- redacts `AUTH` payloads from logs.

## Install

```sh
cargo install --path .
```

Needs a recent Rust toolchain. No C compiler, no system libraries.

## Getting started

```sh
pigeon
```

That is the whole setup. With no config, the reader opens a wizard on the same
screen:

1. **Passphrase** — creates the encrypted vault (or unlocks it on later runs).
2. **Your account** — email address, name, password.
3. **Servers** — already filled in. pigeon looks your address up in a built-in
   table of ~25 providers, then in Mozilla's autoconfig database over the
   network, and falls back to `imap.<domain>` / `smtp.<domain>`. Ports follow the
   transport you pick, so TLS/STARTTLS mismatches are hard to create.
4. **Check** — it actually logs in to IMAP and SMTP and reports what happened
   before writing anything.

The password goes to your OS keyring; if no keyring answers (headless boxes,
containers, a locked login keyring) it goes into the encrypted vault instead, and
the generated config records which one was used. The config is written `0600`.

Gmail and Outlook are detected automatically and the OAuth2 toggle is preselected
— finish the browser sign-in with `pigeon auth login <account>` after setup. The
flow uses PKCE over a loopback redirect, so pigeon never sees your password.

Everything is reachable from the CLI too, if you prefer it:

```sh
pigeon doctor                        # check config and reach every server
pigeon auth store personal imap      # password → OS keyring
```

## Configuration

`~/.config/pigeon/config.toml`:

```toml
[general]
encrypt_at_rest = true
unlock = "prompt"          # prompt | keyring | command
# unlock_command = "pass show pigeon/vault"
poll_interval_secs = 300
idle = true
notify = true
default_account = "personal"

[ui]
theme = "default-dark"     # default-dark default-light gruvbox-dark nord mono
layout = "three-pane"
threading = true
relative_dates = true
vim_keys = true

[[account]]
name = "personal"
address = "you@example.org"
display_name = "Your Name"
aliases = ["you+lists@example.org"]

[account.imap]
host = "imap.example.org"
port = 993
security = "tls"           # tls | starttls | none
user = "you@example.org"
auth = "keyring"           # keyring | password | password-command | oauth2 | none

[account.smtp]
host = "smtp.example.org"
port = 465
security = "tls"
auth = "keyring"

[account.folders]
inbox = "INBOX"
sent = "Sent"
drafts = "Drafts"
trash = "Trash"
archive = "Archive"

[account.pgp]
enabled = true
sign_by_default = true
encrypt_policy = "if-possible"   # never | if-possible | always
secret_key_file = "~/.pigeon/keys/you.sec.asc"

[bindings]
x = "archive"              # rebind a key
D = ""                     # or unbind one
```

## Keys

`?` shows the full list, always generated from the live keymap so it cannot go
stale. Highlights:

| Key | Action | Key | Action |
|---|---|---|---|
| `j`/`k` | move | `c` | compose |
| `tab` | next pane | `r` / `R` | reply / reply all |
| `enter` | open | `F` | forward |
| `space` | expand thread | `d` / `D` | trash / delete permanently |
| `n` / `p` | next / prev unread | `e` | archive |
| `/` | search | `m` / `y` | move / copy |
| `v` | mark message | `a` | attachments |
| `t` / `f` | toggle read / flag | `h` | HTML ⇄ plain text |
| `s` / `S` | sync folder / all | `I` | allow remote images |
| `C-p` | command palette | `u` | raw source |
| `:` | command line | `B` | outbox |

Account upkeep happens in the reader as well — `:passwd [account]` sets the IMAP
password and `:smtp-passwd` the SMTP one, both typed into a masked prompt and
stored the same way the wizard stores them. `:accounts` lists what is configured.

## Search

The same query language drives local search, and is translated to IMAP `SEARCH`
for the parts a server can answer:

```
from:alice subject:"weekly report" is:unread has:attachment after:7d -in:spam
(from:alice OR from:bob) larger:5M
```

Fields: `from` `to` `cc` `bcc` `subject` `body` `list` `tag` `attachment` `in`
`account`. States: `is:unread|read|flagged|answered|draft|deleted|forwarded|junk|attachment|encrypted|signed|unsigned`.
Ranges: `before:` `after:` `on:` (`2026-01-31`, `today`, `yesterday`, `7d`, `2w`),
`larger:` `smaller:` (`5M`, `200k`). `-` negates, `OR` alternates, parentheses group.

## How syncing works

One task per account: connect, sync, then **IDLE** on the inbox so new mail
arrives without polling. Failures back off exponentially to a five-minute ceiling.

- `UIDVALIDITY` changes drop the local copy of that folder — every cached UID now
  refers to a different message.
- `CONDSTORE` (when offered) fetches only the flags that moved since the last
  sync instead of re-reading every envelope.
- A full UID list detects server-side expunges, which a forward-only client
  would otherwise never notice.
- `MOVE` is used when advertised, with a copy/flag/expunge fallback when not.

Actions taken offline queue as pending operations and replay on reconnect, each
dropped from the queue only after the server accepts it. Outgoing mail queues in
an outbox with per-message backoff; `B` shows it and `C-o` retries.

## Composing

`c`, `r`, `R`, `F` open your `$EDITOR` on a draft with editable headers:

```
To: alice@example.org
Cc:
Bcc:
Subject: Re: compiler design
Attach: ~/notes.pdf, ~/chart.png
Sign: yes
Encrypt: no
--- write your message below this line ---

Your reply here.
```

Save and quit to queue it; empty the body to cancel.

## Commands

```
pigeon                    open the reader (runs setup on first launch)
pigeon daemon             run headless, serving a unix socket (see below)
pigeon sync [ACCOUNT]     synchronise once and exit
pigeon send               flush the outbox
pigeon doctor             check config and reach every server
pigeon auth store A KIND  store an IMAP or SMTP password in the OS keyring
pigeon auth login A       OAuth2 browser flow
pigeon auth forget A      remove stored secrets
pigeon vault passwd       change the vault passphrase
pigeon vault info         vault and database status
pigeon pgp list|import|export
```

## Layout

```
src/
  crypto/     vault (Argon2id + XChaCha20-Poly1305), AEAD wrapper, blind index
  store/      encrypted redb: envelopes, folders, blobs, outbox, pending ops
  mail/       MIME parsing, body rendering, HTML sanitiser, JWZ threading,
              query language, composition
  net/        TLS (graviola), IMAP, hand-written SMTP and HTTPS, OAuth2 PKCE,
              provider autoconfiguration
  sync/       per-account sync engine, IDLE, offline replay, outbox
  ui/         ratatui front end: state, rendering, keymap, compose, themes,
              first-run wizard, form fields
  daemon/     headless mode: unix socket, JSON protocol, account setup
  pgp.rs      OpenPGP through rpgp
  secrets.rs  keyring, password commands, passphrase prompt
```

## Status

Working: in-app setup wizard with provider autodetection and live connection
testing, multi-account IMAP with IDLE and CONDSTORE, encrypted local store with
blind-index search, JWZ threading, the three-pane reader, compose/reply/forward
through `$EDITOR`, an offline queue and outbox, OAuth2, attachments, desktop
notifications, themes, and a configurable keymap.

Not yet wired to the terminal UI: the OpenPGP module is complete and tested but
the sign/encrypt actions still report that it is unconfigured; server-side
`SEARCH` is implemented in the IMAP layer but not bound to a key; the rules
engine in `[[rule]]` parses but does not yet run; adding a *second* account from
the TUI still means editing the config by hand, though `pigeon daemon` can do it
over the socket. S/MIME is not supported.

## Headless mode

`pigeon daemon` runs without a terminal and serves a unix socket, so a desktop
shell, a status bar or a script can read and act on your mail while pigeon keeps
the store, the sync engine and the keys. The reference front end is the taloshell
Quickshell config, whose `Pigeon` service speaks this protocol.

```
pigeon daemon                                   # $XDG_RUNTIME_DIR/pigeon/daemon.sock
pigeon daemon --socket /run/user/1000/mail.sock
```

The socket lives in `$XDG_RUNTIME_DIR` (mode 0700) and is itself created 0600,
which is what makes it safe to send a vault passphrase over it. There is no
network listener and no authentication beyond those file permissions: anything
that can open the socket is already running as you.

### Protocol

One JSON object per line, in both directions. A request carries an `id`, a
`method` and optional `params`; the reply carries the same `id` and either
`result` or `error`:

```json
{"id":1,"method":"messages","params":{"folder":"INBOX","limit":20}}
{"id":1,"ok":true,"result":{"account":"work","folder":"INBOX","total":97,"messages":[…]}}
```

After `subscribe`, the daemon also pushes unsolicited lines carrying an `event`
instead of an `id` — `new-mail`, `flags`, `removed`, `folders`, `status`,
`unread`, `outbox`, `sent`, `notice`, `error`, `locked`, `unlocked`. If no client
is subscribed, new mail falls back to a desktop notification, so nothing is lost
when the shell is not running.

Reading and acting on mail:

```
hello                     version, and whether the vault is locked
status                    accounts, unread totals, outbox depth
unlock {passphrase}       unlock the vault; lock  puts the keys back
folders [account]         folder list with roles, icons and unread counts
messages {account, folder, limit, offset, unread, flagged}
threads {account, folder} JWZ threads rather than a flat list
message {account, folder, uid, html, width}
                          envelope plus the rendered body, downloading it if
                          the body is not cached yet
search {query, limit}     the same query language as the reader
mark {keys, seen, flagged, answered, draft, junk}
move / copy {keys, to}    delete {keys, permanent}
send / draft {…}          queues through the outbox, so it works offline
attachment {…, part}      writes the part out 0600 and returns the path
sync {account, folder}    flush  sends whatever is waiting
```

Setting pigeon up, so a shell can own the whole first run:

```
vault-status              does a vault exist, and is it locked
vault-create {passphrase}
autoconfig {email}        provider lookup: built-in table, then Mozilla's ISPDB
test-account {…}          real IMAP and SMTP logins, reported separately
account-add {…}           writes the config, files the password in the keyring
                          or the vault, and restarts the sync engine
account-update / account-remove / set-password
settings-get / settings-set
```

The daemon unlocks itself at startup when `unlock` is `keyring` or `command`,
and otherwise serves in a locked state until a client sends `unlock` — which is
what lets a shell prompt for the passphrase in its own UI.

A config written from the socket goes through the same lossless writer the setup
wizard uses, so `[[rule]]` blocks, `[bindings]` and hand-edited settings survive
being rewritten.


## Licence

MIT
