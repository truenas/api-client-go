# TrueNAS API Client for Go

A Go port of the [TrueNAS websocket client](https://github.com/truenas/api_client),
providing a client library and the `midclt` command-line tool for the TrueNAS
middleware API over a JSON-RPC 2.0 websocket connection.

Requires TrueNAS 25.04 or later (the JSON-RPC 2.0 endpoint,
`/api/current`); the pre-25.04 legacy `/websocket` protocol is not
implemented. See [PLAN.md](PLAN.md) for porting status.

## Packages

- `github.com/truenas/api-client-go` (package `truenas`) — the client.
- `github.com/truenas/api-client-go/ejson` — the extended JSON codec used by
  the middleware API (`$date`, `$time`, `$set`, ...).
- `github.com/truenas/api-client-go/scram` — client side of the
  SCRAM-SHA-512 exchange with RFC 5929 channel binding.
- `github.com/truenas/api-client-go/cmd/midclt` — the CLI.

## Library usage

```go
import truenas "github.com/truenas/api-client-go"

// Local IPC (the middlewared UNIX socket) — pass "" as the URI.
// Remote: "wss://truenas.example.com/api/current".
c, err := truenas.Connect("wss://truenas.example.com/api/current", nil)
if err != nil {
    log.Fatal(err)
}
defer c.Close()

// Authenticate with an API key (SCRAM-SHA-512 with TLS channel binding by
// default; the key is never sent over the wire):
if err := c.LoginWithAPIKey("admin", "1-abcd...", nil); err != nil {
    log.Fatal(err)
}
// ...or with a password (and optional OTP token):
// err = c.LoginWithPassword("admin", "password", "")

// Plain calls:
info, err := c.Call("system.info")

// Long-running jobs, with progress:
job, err := c.StartJob(ctx, "pool.scrub.scrub", "tank")
job.OnUpdate(func(f *truenas.JobFields) {
    log.Printf("%.0f%% %s", f.Progress.Percent, f.Progress.Description)
})
result, err := job.Result(ctx)

// Event subscriptions:
sub, err := c.Subscribe("core.get_jobs", func(mtype string, params *truenas.CollectionUpdateParams) {
    log.Println(mtype, string(params.Fields))
}, nil)
defer c.Unsubscribe(sub)
```

## midclt

```console
$ go build ./cmd/midclt
$ midclt ping
$ midclt call system.info
$ midclt call user.query '[["username", "=", "root"]]'
$ midclt -u ws://nas.example/api/current -U admin -P secret call system.info
$ midclt -K /root/apikey.json -U admin call user.create - < new_user.json
$ midclt call -j pool.import_on_boot
$ midclt subscribe -n 1 core.get_jobs
```

## License

LGPL-3.0-or-later, same as the Python client.
