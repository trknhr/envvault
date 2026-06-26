package clerr_test

import (
	"errors"
	"testing"

	"github.com/trknhr/envvault/internal/clerr"
)

func TestErrorFormatsCodeWithoutSecretDetail(t *testing.T) {
	err := clerr.New(clerr.ReferenceInvalid, "query and fragment are not allowed")

	if got, want := err.Error(), "ENVVAULT_REFERENCE_INVALID: query and fragment are not allowed"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestCodeOfFindsWrappedEnvVaultError(t *testing.T) {
	err := errors.Join(errors.New("outer"), clerr.New(clerr.ProfileNotFound, "backend-a/dev"))

	if got, ok := clerr.CodeOf(err); !ok || got != clerr.ProfileNotFound {
		t.Fatalf("CodeOf() = %q, %v; want %q, true", got, ok, clerr.ProfileNotFound)
	}
}
