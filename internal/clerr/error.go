package clerr

import (
	"errors"
	"fmt"
)

type Code string

const (
	ConfigInvalid         Code = "CREDLEASE_CONFIG_INVALID"
	ProfileNotFound       Code = "CREDLEASE_PROFILE_NOT_FOUND"
	ProfileKindMismatch   Code = "CREDLEASE_PROFILE_KIND_MISMATCH"
	ProjectNotTrusted     Code = "CREDLEASE_PROJECT_NOT_TRUSTED"
	KeyringUnavailable    Code = "CREDLEASE_KEYRING_UNAVAILABLE"
	KeyringLocked         Code = "CREDLEASE_KEYRING_LOCKED"
	ParentKeyMissing      Code = "CREDLEASE_PARENT_KEY_MISSING"
	RuntimeUnavailable    Code = "CREDLEASE_RUNTIME_UNAVAILABLE"
	RuntimeIncompatible   Code = "CREDLEASE_RUNTIME_INCOMPATIBLE"
	IssueFailed           Code = "CREDLEASE_ISSUE_FAILED"
	ReferenceInvalid      Code = "CREDLEASE_REFERENCE_INVALID"
	BrowserExchangeFailed Code = "CREDLEASE_BROWSER_EXCHANGE_FAILED"
	BrowserURLRejected    Code = "CREDLEASE_BROWSER_URL_REJECTED"
	CleanupFailed         Code = "CREDLEASE_CLEANUP_FAILED"
	LockTimeout           Code = "CREDLEASE_LOCK_TIMEOUT"
)

type Error struct {
	Code    Code
	Message string
	Err     error
}

func New(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}

func Wrap(code Code, message string, err error) *Error {
	return &Error{Code: code, Message: message, Err: err}
}

func (e *Error) Error() string {
	if e.Message == "" {
		return string(e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Err
}

func CodeOf(err error) (Code, bool) {
	var credleaseErr *Error
	if errors.As(err, &credleaseErr) {
		return credleaseErr.Code, true
	}
	return "", false
}
