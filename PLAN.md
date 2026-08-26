# Porting plan: truenas_api_client (Python) → Go

Source: `truenas_api_client` Python package (JSON-RPC 2.0 websocket client for
TrueNAS middleware). This repo ports it to Go in chunks; each chunk lands with
tests.

## Layout

- `github.com/truenas/api-client-go` — root package `truenas`: client, errors,
  JSON-RPC types, auth.
- `ejson/` — extended JSON codec.
- `cmd/midclt/` — CLI.

## Chunks

- [x] **1. Scaffold + foundations**
  - git repo, go.mod, LICENSE (LGPL-3.0-or-later, same as upstream)
  - `ejson`: `$date` (ms since epoch), `$time`, `{"$type": "date"}`, `$set`,
    `$ipv4_interface`/`$ipv6_interface` (ports `ejson.py`)
  - JSON-RPC 2.0 message types and error codes (ports `jsonrpc.py`)
  - Errors: `ClientError`, `ValidationErrors`, `CallTimeoutError`, errno
    constants 201-210 (ports `exc.py`)
- [ ] **2. Core client**
  - websocket transport: unix socket (`ws+unix://`), `ws://`/`wss://`,
    reserved ports (600-1024, ws:// only), `verify_ssl` toggle, TCP keepalive
    (ports `WSClient`)
  - call/response correlation by uuid, `core.set_options` handshake
    (`legacy_jobs: false`), call timeout, connection-closed error broadcast
    (ports `JSONRPCClient` call path)
- [ ] **3. Jobs + subscriptions**
  - `core.get_jobs` subscription, new-style jobs (result delivered via
    collection_update `message_ids`), `Job` wait/result, validation/exc_info
    error mapping
  - `Subscribe`/`Unsubscribe`, `collection_update` + `notify_unsubscribed`
    dispatch, sync vs async callbacks
- [ ] **4. Auth**
  - `LoginWithPassword` (`auth.login_ex` PASSWORD_PLAIN, OTP continue, legacy
    `auth.login` fallback) (ports `login_with_password`)
  - API key: key-material parsing (raw `<id>-<key>`, JSON, INI file),
    PLAIN (`API_KEY_PLAIN`), SCRAM-SHA-512 with RFC 5929
    tls-server-end-point channel binding (ports `auth_api_key.py`,
    `scram_impl.py`, client-side subset of `py_scram/`)
- [ ] **5. CLI `midclt`** (`cmd/midclt`)
  - call / ping / subscribe subcommands, job progress (progressbar or
    description), stdin `-` payload, `--insecure`, `--plain`,
    `--no-channel-binding`
- [ ] **6. Deferred / dropped**
  - Legacy pre-25.04 `/websocket` client (`legacy.py`): deferred, port only if
    needed
  - `py_exceptions` / pickle support: dropped (Python-specific)
