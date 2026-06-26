package clerr

import (
	"errors"
	"fmt"
)

type Code string

const (
	ConfigInvalid         Code = "ENVVAULT_CONFIG_INVALID"
	ProfileNotFound       Code = "ENVVAULT_PROFILE_NOT_FOUND"
	ProfileKindMismatch   Code = "ENVVAULT_PROFILE_KIND_MISMATCH"
	ProjectNotTrusted     Code = "ENVVAULT_PROJECT_NOT_TRUSTED"
	KeyringUnavailable    Code = "ENVVAULT_KEYRING_UNAVAILABLE"
	KeyringLocked         Code = "ENVVAULT_KEYRING_LOCKED"
	ParentKeyMissing      Code = "ENVVAULT_PARENT_KEY_MISSING"
	RuntimeUnavailable    Code = "ENVVAULT_RUNTIME_UNAVAILABLE"
	RuntimeIncompatible   Code = "ENVVAULT_RUNTIME_INCOMPATIBLE"
	IssueFailed           Code = "ENVVAULT_ISSUE_FAILED"
	ReferenceInvalid      Code = "ENVVAULT_REFERENCE_INVALID"
	BrowserExchangeFailed Code = "ENVVAULT_BROWSER_EXCHANGE_FAILED"
	BrowserURLRejected    Code = "ENVVAULT_BROWSER_URL_REJECTED"
	CleanupFailed         Code = "ENVVAULT_CLEANUP_FAILED"
	LockTimeout           Code = "ENVVAULT_LOCK_TIMEOUT"
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
	var envvaultErr *Error
	if errors.As(err, &envvaultErr) {
		return envvaultErr.Code, true
	}
	return "", false
}
