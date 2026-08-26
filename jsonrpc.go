// SPDX-License-Identifier: LGPL-3.0-or-later

// Package truenas provides a client for the TrueNAS middleware API over a
// JSON-RPC 2.0 websocket connection.
//
// This is a Go port of the truenas_api_client Python package.
package truenas

import (
	"encoding/json"
	"fmt"
)

// JSON-RPC 2.0 error codes (https://www.jsonrpc.org/specification), plus
// TrueNAS custom codes in the -32000..-32099 range.
type JSONRPCErrorCode int

const (
	InvalidJSON    JSONRPCErrorCode = -32700
	InvalidRequest JSONRPCErrorCode = -32600
	MethodNotFound JSONRPCErrorCode = -32601
	InvalidParams  JSONRPCErrorCode = -32602
	InternalError  JSONRPCErrorCode = -32603

	TruenasTooManyConcurrentCalls JSONRPCErrorCode = -32000
	TruenasCallError              JSONRPCErrorCode = -32001
)

func (c JSONRPCErrorCode) String() string {
	switch c {
	case InvalidJSON:
		return "INVALID_JSON"
	case InvalidRequest:
		return "INVALID_REQUEST"
	case MethodNotFound:
		return "METHOD_NOT_FOUND"
	case InvalidParams:
		return "INVALID_PARAMS"
	case InternalError:
		return "INTERNAL_ERROR"
	case TruenasTooManyConcurrentCalls:
		return "TRUENAS_TOO_MANY_CONCURRENT_CALLS"
	case TruenasCallError:
		return "TRUENAS_CALL_ERROR"
	default:
		return fmt.Sprintf("JSONRPCError(%d)", int(c))
	}
}

// JobProgress reports a job's completion percentage and status text.
type JobProgress struct {
	Percent     float64 `json:"percent"`
	Description string  `json:"description"`
}

// ErrorExtra is one validation error item. On the wire it is a 3-element
// array: [attribute, errmsg, errcode].
type ErrorExtra struct {
	Attribute string
	Errmsg    string
	Errcode   int
}

func (e ErrorExtra) MarshalJSON() ([]byte, error) {
	return json.Marshal([]any{e.Attribute, e.Errmsg, e.Errcode})
}

func (e *ErrorExtra) UnmarshalJSON(data []byte) error {
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	if len(arr) != 3 {
		return fmt.Errorf("ErrorExtra: expected 3 elements, got %d", len(arr))
	}
	if err := json.Unmarshal(arr[0], &e.Attribute); err != nil {
		return fmt.Errorf("ErrorExtra attribute: %w", err)
	}
	if err := json.Unmarshal(arr[1], &e.Errmsg); err != nil {
		return fmt.Errorf("ErrorExtra errmsg: %w", err)
	}
	if err := json.Unmarshal(arr[2], &e.Errcode); err != nil {
		return fmt.Errorf("ErrorExtra errcode: %w", err)
	}
	return nil
}

// ExcInfo describes the exception behind a failed job.
type ExcInfo struct {
	Type  string       `json:"type"`
	Extra []ErrorExtra `json:"extra"`
	Repr  string       `json:"repr"`
}

// JobFields is the server-side state of a job as delivered in core.get_jobs
// collection updates.
type JobFields struct {
	ID         json.Number     `json:"id"`
	State      string          `json:"state"`
	Progress   JobProgress     `json:"progress"`
	Result     json.RawMessage `json:"result"`
	ExcInfo    *ExcInfo        `json:"exc_info"`
	Error      string          `json:"error"`
	Exception  string          `json:"exception"`
	MessageIDs []string        `json:"message_ids"`
}

// CollectionUpdateParams is the params object of a collection_update
// notification.
type CollectionUpdateParams struct {
	Msg        string          `json:"msg"`
	Collection string          `json:"collection"`
	ID         json.RawMessage `json:"id"`
	Fields     json.RawMessage `json:"fields"`
	Extra      json.RawMessage `json:"extra"`
}

// Traceback carries server-side traceback information for an error.
type Traceback struct {
	Class     string           `json:"class"`
	Frames    []map[string]any `json:"frames"`
	Formatted string           `json:"formatted"`
	Repr      string           `json:"repr"`
}

// TruenasError is the data member of a TrueNAS JSON-RPC error object.
type TruenasError struct {
	Error   int          `json:"error"`
	Errname string       `json:"errname"`
	Reason  string       `json:"reason"`
	Trace   *Traceback   `json:"trace"`
	Extra   []ErrorExtra `json:"extra"`
}

// NotifyUnsubscribedParams is the params object of a notify_unsubscribed
// notification.
type NotifyUnsubscribedParams struct {
	Collection string        `json:"collection"`
	Error      *TruenasError `json:"error"`
}

// errorObj is the error member of a JSON-RPC error response.
type errorObj struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// message is any incoming JSON-RPC 2.0 message: a Notification (method set)
// or a Response (id set, one of result/error set).
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      *string         `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *errorObj       `json:"error,omitempty"`
}

// request is an outgoing JSON-RPC 2.0 request.
type request struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	ID      string `json:"id"`
	Params  []any  `json:"params"`
}
