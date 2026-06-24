package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	code, err := parseCode(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	os.Exit(code)
}

func parseCode(args []string) (int, error) {
	flags := flag.NewFlagSet("exit-code", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	code := flags.Int("code", 0, "exit code")
	if err := flags.Parse(args); err != nil {
		return 0, err
	}
	if flags.NArg() != 0 {
		return 0, fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if *code < 0 || *code > 125 {
		return 0, fmt.Errorf("--code must be between 0 and 125")
	}
	return *code, nil
}
