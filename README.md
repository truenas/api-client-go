# TrueNAS API Client for Go

A Go port of the [TrueNAS websocket client](https://github.com/truenas/api_client),
providing a client for the TrueNAS middleware API over a JSON-RPC 2.0
websocket connection.

**Status: work in progress.** See [PLAN.md](PLAN.md) for porting progress.

## Packages

- `github.com/truenas/api-client-go` (package `truenas`) — the client.
- `github.com/truenas/api-client-go/ejson` — the extended JSON codec used by
  the middleware API (`$date`, `$time`, `$set`, ...).

## License

LGPL-3.0-or-later, same as the Python client.
