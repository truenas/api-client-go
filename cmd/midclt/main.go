// SPDX-License-Identifier: LGPL-3.0-or-later

// Command midclt is a command-line client for the TrueNAS middleware API,
// a Go port of the Python midclt tool.
//
// When run locally on a TrueNAS server, midclt uses the middleware UNIX
// socket by default. Pass --uri to reach a remote server over a WebSocket
// (the JSON-RPC 2.0 endpoint, e.g. ws://host/api/current, on TrueNAS 25.04
// and later).
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	truenas "github.com/truenas/api-client-go"
	"github.com/truenas/api-client-go/ejson"
)

const usageText = `Usage: midclt [options] <subcommand> [subcommand options] ...

Command-line client for the TrueNAS middleware API.

Options:
  -u, --uri URI            WebSocket URI of the TrueNAS server, e.g.
                           ws(s)://host/api/current (TrueNAS 25.04+, JSON-RPC 2.0).
                           Defaults to the local middleware UNIX socket.
  -U, --username USERNAME  Username for authentication (with -P or -K).
  -P, --password PASSWORD  Password for authentication. Prompted interactively
                           if -U is given without -P or -K.
  -K, --api-key KEY        API key string, or path to a file containing the key.
  -t, --timeout SECONDS    Timeout in seconds for the API call.
      --insecure           Disable SSL certificate verification
                           (WARNING: not for production).
      --no-channel-binding Disable SCRAM-PLUS channel binding for API-key login.
      --plain              Authenticate the API key using PLAIN instead of SCRAM.
                           WARNING: transmits the raw API key.

Subcommands:
  call [-q] [-j] [-jp progressbar|description] METHOD [ARGS...]
        Call a TrueNAS API method. Arguments are parsed as JSON when possible,
        otherwise passed as strings. Use '-' as the final argument to read one
        JSON payload from stdin.
  ping
        Call core.ping on the server and print the response.
  subscribe [-n N] [-t SECONDS] EVENT
        Receive event messages in a continuous stream.

Examples:
  midclt ping
  midclt call system.info
  midclt call user.query '[["username", "=", "root"]]'
  midclt -t 120 call interface.sync true
  midclt --job --job-print description call pool.import_on_boot
  midclt -u ws://nas.example/api/current -U admin -P secret call system.info
  midclt -K /root/apikey.json call user.create - < new_user.json
  midclt subscribe -n 1 core.get_jobs
`

type globalOptions struct {
	uri              string
	username         string
	password         string
	apiKey           string
	timeout          int
	insecure         bool
	noChannelBinding bool
	plain            bool
}

func main() {
	os.Exit(run())
}

func run() int {
	flags := flag.NewFlagSet("midclt", flag.ExitOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, usageText) }

	var opts globalOptions
	flags.StringVar(&opts.uri, "u", "", "")
	flags.StringVar(&opts.uri, "uri", "", "")
	flags.StringVar(&opts.username, "U", "", "")
	flags.StringVar(&opts.username, "username", "", "")
	flags.StringVar(&opts.password, "P", "", "")
	flags.StringVar(&opts.password, "password", "", "")
	flags.StringVar(&opts.apiKey, "K", "", "")
	flags.StringVar(&opts.apiKey, "api-key", "", "")
	flags.IntVar(&opts.timeout, "t", 0, "")
	flags.IntVar(&opts.timeout, "timeout", 0, "")
	flags.BoolVar(&opts.insecure, "insecure", false, "")
	flags.BoolVar(&opts.noChannelBinding, "no-channel-binding", false, "")
	flags.BoolVar(&opts.plain, "plain", false, "")
	flags.Parse(os.Args[1:])

	args := flags.Args()
	if len(args) == 0 {
		flags.Usage()
		return 0
	}

	if opts.username != "" && opts.password == "" && opts.apiKey == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read password: %v\n", err)
			return 1
		}
		opts.password = string(pw)
	}

	switch args[0] {
	case "call":
		return runCall(&opts, args[1:])
	case "ping":
		return runPing(&opts)
	case "subscribe":
		return runSubscribe(&opts, args[1:])
	default:
		flags.Usage()
		return 1
	}
}

func connect(opts *globalOptions) (*truenas.Client, int) {
	c, err := truenas.Connect(opts.uri, &truenas.Options{InsecureSkipVerify: opts.insecure})
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "x509:") || strings.Contains(msg, "certificate"):
			fmt.Fprintln(os.Stderr, "SSL certificate verification failed.")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "You can either:")
			fmt.Fprintln(os.Stderr, "  1. Install the server's SSL certificate in your system's trust store")
			fmt.Fprintln(os.Stderr, "  2. Use the --insecure flag to disable SSL verification (not recommended for production)")
		case strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such file"):
			fmt.Fprintln(os.Stderr, "Failed to run middleware call. Daemon not running?")
		default:
			fmt.Fprintln(os.Stderr, msg)
		}
		return nil, 1
	}
	return c, 0
}

func login(c *truenas.Client, opts *globalOptions) error {
	switch {
	case opts.username != "" && opts.password != "":
		return c.LoginWithPassword(opts.username, opts.password, "")
	case opts.apiKey != "":
		mech := truenas.AuthMechSCRAM
		if opts.plain {
			mech = truenas.AuthMechPlain
		}
		return c.LoginWithAPIKey(opts.username, opts.apiKey, &truenas.APIKeyOptions{
			Mechanism:             mech,
			DisableChannelBinding: opts.noChannelBinding,
		})
	}
	return nil
}

func runPing(opts *globalOptions) int {
	c, code := connect(opts)
	if c == nil {
		return code
	}
	defer c.Close()
	result, err := c.Ping()
	if err != nil || result == "" {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return 1
	}
	fmt.Println(result)
	return 0
}

func runCall(opts *globalOptions, args []string) int {
	flags := flag.NewFlagSet("midclt call", flag.ExitOnError)
	quiet := flags.Bool("q", false, "Suppress error output on API call failure.")
	flags.BoolVar(quiet, "quiet", false, "")
	job := flags.Bool("j", false, "Treat the call as a long-running job and track progress.")
	flags.BoolVar(job, "job", false, "")
	jobPrint := flags.String("jp", "progressbar", "How to render job progress: progressbar or description.")
	flags.StringVar(jobPrint, "job-print", "progressbar", "")
	flags.Parse(args)

	if flags.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "midclt call: METHOD is required")
		return 1
	}
	if *jobPrint != "progressbar" && *jobPrint != "description" {
		fmt.Fprintln(os.Stderr, "midclt call: --job-print must be 'progressbar' or 'description'")
		return 1
	}
	method := flags.Arg(0)
	params, err := parseParams(flags.Args()[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	c, code := connect(opts)
	if c == nil {
		return code
	}
	defer c.Close()

	if err := login(c, opts); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to login: ", err)
		return 1
	}

	ctx := context.Background()
	if opts.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.timeout)*time.Second)
		defer cancel()
	}

	var result any
	if *job {
		result, err = callJob(ctx, c, method, params, *jobPrint)
	} else {
		if opts.timeout == 0 {
			result, err = c.Call(method, params...)
		} else {
			result, err = c.CallContext(ctx, method, params...)
		}
	}
	if err != nil {
		if !*quiet {
			printCallError(err)
		}
		return 1
	}

	printResult(result)
	return 0
}

func callJob(ctx context.Context, c *truenas.Client, method string, params []any, jobPrint string) (any, error) {
	job, err := c.StartJob(ctx, method, params...)
	if err != nil {
		return nil, err
	}

	if jobPrint == "progressbar" {
		bar := newProgressBar(os.Stderr)
		job.OnUpdate(func(fields *truenas.JobFields) {
			bar.update(fields.Progress.Percent, fields.Progress.Description)
		})
		result, err := job.Result(context.Background())
		bar.finish()
		return result, err
	}

	// description mode: print each new status line, suitable for logs.
	lastDesc := ""
	job.OnUpdate(func(fields *truenas.JobFields) {
		desc := fields.Progress.Description
		if desc != "" && desc != lastDesc {
			fmt.Fprintln(os.Stderr, desc)
		}
		lastDesc = desc
	})
	return job.Result(context.Background())
}

func runSubscribe(opts *globalOptions, args []string) int {
	flags := flag.NewFlagSet("midclt subscribe", flag.ExitOnError)
	number := flags.Int("n", 0, "Exit after receiving this many events.")
	flags.IntVar(number, "number", 0, "")
	timeout := flags.Int("t", 0, "Stop waiting after this many seconds.")
	flags.IntVar(timeout, "timeout", 0, "")
	flags.Parse(args)

	if flags.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "midclt subscribe: EVENT is required")
		return 1
	}
	event := flags.Arg(0)

	c, code := connect(opts)
	if c == nil {
		return code
	}
	defer c.Close()

	done := make(chan struct{})
	received := 0
	sub, err := c.Subscribe(event, func(mtype string, params *truenas.CollectionUpdateParams) {
		data, err := json.Marshal(params)
		if err != nil {
			return
		}
		fmt.Println(string(data))
		received++
		if *number > 0 && received >= *number {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	}, &truenas.SubscribeOptions{Sync: true})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	var timeoutCh <-chan time.Time
	if *timeout > 0 {
		timeoutCh = time.After(time.Duration(*timeout) * time.Second)
	}
	select {
	case <-done:
	case <-sub.Done():
		if err := sub.Err(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	case <-timeoutCh:
		return 1
	}
	return 0
}

// parseParams converts CLI arguments: each argument is parsed as JSON when
// possible, otherwise passed as a raw string. '-' reads a single JSON payload
// from stdin (cached across repeats), useful for keeping secrets out of shell
// history and process listings.
func parseParams(args []string) ([]any, error) {
	var stdinContent *string
	params := make([]any, 0, len(args))
	for _, arg := range args {
		if arg == "-" {
			if stdinContent == nil {
				if term.IsTerminal(int(os.Stdin.Fd())) {
					return nil, fmt.Errorf("Error: Cannot read from stdin when connected to a terminal.\n" +
						"Please pipe input or provide the argument directly.")
				}
				data, err := io.ReadAll(os.Stdin)
				if err != nil {
					return nil, fmt.Errorf("failed to read stdin: %w", err)
				}
				s := string(data)
				stdinContent = &s
			}
			params = append(params, parseArg(*stdinContent))
			continue
		}
		params = append(params, parseArg(arg))
	}
	return params, nil
}

func parseArg(arg string) any {
	if value, err := ejson.Unmarshal([]byte(arg)); err == nil {
		return value
	}
	return arg
}

func printResult(result any) {
	switch v := result.(type) {
	case int64:
		fmt.Println(v)
	case string:
		fmt.Println(v)
	default:
		data, err := ejson.Marshal(result)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		fmt.Println(string(data))
	}
}

func printCallError(err error) {
	var clientErr *truenas.ClientError
	if errors.As(err, &clientErr) {
		if clientErr.Reason != "" {
			fmt.Fprintln(os.Stderr, clientErr.Reason)
		}
		if clientErr.Trace != nil && clientErr.Trace.Formatted != "" {
			fmt.Fprintln(os.Stderr, clientErr.Trace.Formatted)
		}
		if len(clientErr.Extra) > 0 {
			for _, extra := range clientErr.Extra {
				fmt.Fprintf(os.Stderr, "%s: %s (%d)\n", extra.Attribute, extra.Errmsg, extra.Errcode)
			}
		}
		return
	}
	fmt.Fprintln(os.Stderr, err)
}
