package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestTerminalCredentialReaderRejectsNonTerminalInput(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "credential-input")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var output bytes.Buffer

	_, err = terminalCredentialReader(file)(&output)

	if err == nil || !strings.Contains(err.Error(), "interactive credential input requires a terminal") {
		t.Fatalf("error = %v, want non-terminal guidance", err)
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q, want empty", output.String())
	}
}
