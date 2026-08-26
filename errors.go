// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"fmt"
	"strings"
)

// Custom TrueNAS error codes (ports ErrnoMixin from exc.py).
const (
	// ENoMethod: service not found or method not found in service.
	ENoMethod = 201
	// EServiceStartFailure: service failed to start.
	EServiceStartFailure = 202
	// EAlertCheckerUnavailable: alert checker unavailable.
	EAlertCheckerUnavailable = 203
	// ERemoteNodeError: remote node responded with an error.
	ERemoteNodeError = 204
	// EDatasetIsLocked: locked datasets.
	EDatasetIsLocked = 205
	// EInvalidRRDTimestamp: invalid RRD timestamp.
	EInvalidRRDTimestamp = 206
	// ENotAuthenticated: client not authenticated.
	ENotAuthenticated = 207
	// ESSLCertVerificationError: SSL certificate/host key could not be verified.
	ESSLCertVerificationError = 208
	// ERebootRequired: system reboot is required.
	ERebootRequired = 209
	// EHAUnavailable: HA is unavailable.
	EHAUnavailable = 210
)

// ClientError represents any error reported through the client, either a
// connection-level failure or an error response from the server (ports
// ClientException from exc.py).
type ClientError struct {
	// Reason is the error message.
	Reason string
	// Errno classifies the error: a standard errno value or one of the
	// custom codes above. Zero means unclassified.
	Errno int
	// Trace holds server-side traceback information, if any.
	Trace *Traceback
	// Extra holds any additional errors pertaining to this one.
	Extra []ErrorExtra
}

func (e *ClientError) Error() string {
	return e.Reason
}

// ValidationErrors is a collection of validation failures reported by the
// server (ports ValidationErrors from exc.py). It is returned when a call
// fails with INVALID_PARAMS.
type ValidationErrors struct {
	Errors []ErrorExtra
}

func (e *ValidationErrors) Error() string {
	msgs := make([]string, 0, len(e.Errors))
	for _, err := range e.Errors {
		attribute := err.Attribute
		if attribute == "" {
			attribute = "ALL"
		}
		msgs = append(msgs, fmt.Sprintf("[%s] %s: %s", errnoName(err.Errcode), attribute, err.Errmsg))
	}
	return strings.Join(msgs, "\n")
}

// CallTimeoutError is returned when a call does not complete within its
// timeout (ports CallTimeout from exc.py).
type CallTimeoutError struct{}

func (e *CallTimeoutError) Error() string {
	return "Call timeout"
}

// errnoName maps an errno value from the server to its symbolic name. The
// server runs Linux, so Linux numbering applies regardless of the client
// platform. Unknown codes map to "EUNKNOWN", like Python's
// errno.errorcode.get(code, 'EUNKNOWN').
func errnoName(code int) string {
	if name, ok := linuxErrnoNames[code]; ok {
		return name
	}
	if name, ok := customErrnoNames[code]; ok {
		return name
	}
	return "EUNKNOWN"
}

var customErrnoNames = map[int]string{
	ENoMethod:                 "ENOMETHOD",
	EServiceStartFailure:      "ESERVICESTARTFAILURE",
	EAlertCheckerUnavailable:  "EALERTCHECKERUNAVAILABLE",
	ERemoteNodeError:          "EREMOTENODEERROR",
	EDatasetIsLocked:          "EDATASETISLOCKED",
	EInvalidRRDTimestamp:      "EINVALIDRRDTIMESTAMP",
	ENotAuthenticated:         "ENOTAUTHENTICATED",
	ESSLCertVerificationError: "ESSLCERTVERIFICATIONERROR",
	ERebootRequired:           "EREBOOTREQUIRED",
	EHAUnavailable:            "EHAUNAVAILABLE",
}

var linuxErrnoNames = map[int]string{
	1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO",
	6: "ENXIO", 7: "E2BIG", 8: "ENOEXEC", 9: "EBADF", 10: "ECHILD",
	11: "EAGAIN", 12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 15: "ENOTBLK",
	16: "EBUSY", 17: "EEXIST", 18: "EXDEV", 19: "ENODEV", 20: "ENOTDIR",
	21: "EISDIR", 22: "EINVAL", 23: "ENFILE", 24: "EMFILE", 25: "ENOTTY",
	26: "ETXTBSY", 27: "EFBIG", 28: "ENOSPC", 29: "ESPIPE", 30: "EROFS",
	31: "EMLINK", 32: "EPIPE", 33: "EDOM", 34: "ERANGE", 35: "EDEADLK",
	36: "ENAMETOOLONG", 37: "ENOLCK", 38: "ENOSYS", 39: "ENOTEMPTY",
	40: "ELOOP", 42: "ENOMSG", 43: "EIDRM", 60: "ENOSTR", 61: "ENODATA",
	62: "ETIME", 63: "ENOSR", 66: "EREMOTE", 71: "EPROTO", 74: "EBADMSG",
	75: "EOVERFLOW", 84: "EILSEQ", 87: "EUSERS", 88: "ENOTSOCK",
	89: "EDESTADDRREQ", 90: "EMSGSIZE", 91: "EPROTOTYPE", 92: "ENOPROTOOPT",
	93: "EPROTONOSUPPORT", 94: "ESOCKTNOSUPPORT", 95: "EOPNOTSUPP",
	96: "EPFNOSUPPORT", 97: "EAFNOSUPPORT", 98: "EADDRINUSE",
	99: "EADDRNOTAVAIL", 100: "ENETDOWN", 101: "ENETUNREACH",
	102: "ENETRESET", 103: "ECONNABORTED", 104: "ECONNRESET",
	105: "ENOBUFS", 106: "EISCONN", 107: "ENOTCONN", 108: "ESHUTDOWN",
	109: "ETOOMANYREFS", 110: "ETIMEDOUT", 111: "ECONNREFUSED",
	112: "EHOSTDOWN", 113: "EHOSTUNREACH", 114: "EALREADY",
	115: "EINPROGRESS", 116: "ESTALE", 122: "EDQUOT", 125: "ECANCELED",
	130: "EOWNERDEAD", 131: "ENOTRECOVERABLE",
}

// Standard Linux errno values used by the client itself when classifying
// connection errors, defined here so they are platform-independent.
const (
	errnoETIMEDOUT    = 110
	errnoECONNABORTED = 103
)
