package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/transfer"
)

func TestTerminalPassphraseReaderRejectsNonTerminalInput(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "passphrase-input")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var output bytes.Buffer

	_, err = terminalPassphraseReader(file)(&output, "Export passphrase: ")

	if err == nil || !strings.Contains(err.Error(), "passphrase requires a terminal") || !strings.Contains(err.Error(), "--passphrase-stdin") {
		t.Fatalf("error = %v, want terminal guidance", err)
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q, want empty", output.String())
	}
}

func TestReadPassphraseStdinKeepsInternalSpaceAndDropsNewline(t *testing.T) {
	got, err := readPassphraseStdin(strings.NewReader("secret phrase\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret phrase" {
		t.Fatalf("passphrase = %q", got)
	}
}

func TestReadPassphraseStdinRejectsTooLongLine(t *testing.T) {
	line := strings.Repeat("a", transfer.MaxPassphraseLen+1) + "\n"
	_, err := readPassphraseStdin(strings.NewReader(line))
	if err == nil || !strings.Contains(err.Error(), "passphrase is too long") {
		t.Fatalf("error = %v, want too long", err)
	}
	if strings.Contains(err.Error(), "aaa") {
		t.Fatalf("error leaked passphrase: %v", err)
	}
}
