// Package toolerr defines a structured tool-error type that MCP tools return
// to clients. Each error carries a stable code (slug) that LLM clients can
// branch on, plus a human-readable message and optional details.
//
// The error type satisfies the standard error interface, and its Is method
// compares by Code so errors.Is works with sentinel values regardless of the
// inner Message.
package toolerr

import "fmt"

// Error is a structured tool error.
type Error struct {
	// Code is a stable slug for client-side branching (e.g. "path_not_allowed").
	Code string `json:"code"`
	// Message is a human-readable summary.
	Message string `json:"message"`
	// Details carries machine-readable context (e.g. the offending filter
	// position, an exit code, candidate field names).
	//
	// Details must never carry packet payload (ADR-0007): errors are logged,
	// and payload in a log is a credential leak.
	Details map[string]any `json:"details,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Is reports whether target is a *Error with the same Code. This lets sentinel
// values like ErrPathNotAllowed work under errors.Is(err, ErrPathNotAllowed)
// regardless of the inner Message and Details.
func (e *Error) Is(target error) bool {
	te, ok := target.(*Error)
	if !ok {
		return false
	}
	return te.Code == e.Code
}

// WithDetails returns a copy of e with the given details attached.
func (e *Error) WithDetails(d map[string]any) *Error {
	cp := *e
	cp.Details = d
	return &cp
}

// New creates an Error.
func New(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Newf creates an Error with a printf-formatted message.
func Newf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Stable error codes used across the tool implementations (architecture §5.1).
// Adding a new code is a no-op for older clients (they fall back to inspecting
// Message), but renaming an existing code is a breaking change.
const (
	// Argument and workspace validation.
	CodeInvalidArguments   = "invalid_arguments"
	CodeMissingArgument    = "missing_argument"
	CodeInvalidWorkspaceID = "invalid_workspace_id"
	CodeWorkspaceNotFound  = "workspace_not_found"

	// Host filesystem access.
	CodePathNotAllowed = "path_not_allowed"
	CodePcapUnreadable = "pcap_unreadable"

	// Analysis.
	CodeInvalidDisplayFilter = "invalid_display_filter"
	CodeContainerFailed      = "container_failed"
	CodeTsharkFailed         = "tshark_failed"

	// Async jobs. A job_not_found simply means "re-run the original tool":
	// jobs are in-memory and results are idempotent (ADR-0006).
	CodeJobNotFound = "job_not_found"
	// CodeAnalysisFailed is the fallback for a background job that failed
	// without producing a more specific code.
	CodeAnalysisFailed = "analysis_failed"
	// CodeInternalError reports a bug in this server — a panic recovered at
	// the request or job boundary. It is never the caller's fault.
	CodeInternalError = "internal_error"

	// Payload tools (ADR-0007). A truncated capture has no payload to
	// extract; that is an answer, not a transient failure, and saying so
	// up front is what stops an agent from retrying forever.
	CodePayloadUnavailableTruncatedCapture = "payload_unavailable_truncated_capture"
	CodeObjectTooLarge                     = "object_too_large"
)
