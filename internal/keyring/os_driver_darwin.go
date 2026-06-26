package keyring

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

const (
	securityPath         = "/usr/bin/security"
	encodingPrefix       = "go-keyring-encoded:"
	base64EncodingPrefix = "go-keyring-base64:"
)

type platformDriver struct{}

func (platformDriver) Get(service, account string) (string, error) {
	return newDarwinSecurityDriver(execDarwinSecurityRunner{}).Get(service, account)
}

func (platformDriver) Set(service, account, password string) error {
	return newDarwinSecurityDriver(execDarwinSecurityRunner{}).Set(service, account, password)
}

func (platformDriver) Delete(service, account string) error {
	return newDarwinSecurityDriver(execDarwinSecurityRunner{}).Delete(service, account)
}

type darwinSecurityRunner interface {
	CombinedOutput(args []string, stdin string) ([]byte, error)
}

type darwinSecurityDriver struct {
	runner darwinSecurityRunner
}

func newDarwinSecurityDriver(runner darwinSecurityRunner) darwinSecurityDriver {
	return darwinSecurityDriver{runner: runner}
}

func (d darwinSecurityDriver) Get(service, account string) (string, error) {
	keychain, err := d.defaultKeychain()
	if err != nil {
		return "", err
	}
	args := []string{"find-generic-password", "-s", service, "-wa", account, keychain}
	out, err := d.runner.CombinedOutput(args, "")
	if err != nil {
		return "", err
	}
	return decodeDarwinPassword(string(out))
}

func (d darwinSecurityDriver) Set(service, account, password string) error {
	keychain, err := d.defaultKeychain()
	if err != nil {
		return err
	}
	encoded := base64EncodingPrefix + base64.StdEncoding.EncodeToString([]byte(password))
	command := fmt.Sprintf(
		"add-generic-password -U -s %s -a %s -w %s %s\n",
		quoteDarwinSecurityWord(service),
		quoteDarwinSecurityWord(account),
		quoteDarwinSecurityWord(encoded),
		quoteDarwinSecurityWord(keychain),
	)
	if len(command) > 4096 {
		return fmt.Errorf("keychain item too large")
	}
	_, err = d.runner.CombinedOutput([]string{"-i"}, command)
	return err
}

func (d darwinSecurityDriver) Delete(service, account string) error {
	keychain, err := d.defaultKeychain()
	if err != nil {
		return err
	}
	args := []string{"delete-generic-password", "-s", service, "-a", account, keychain}
	_, err = d.runner.CombinedOutput(args, "")
	return err
}

func (d darwinSecurityDriver) defaultKeychain() (string, error) {
	out, err := d.runner.CombinedOutput([]string{"default-keychain"}, "")
	if err != nil {
		return "", err
	}
	keychain := strings.TrimSpace(string(out))
	keychain = strings.Trim(keychain, `"`)
	if keychain == "" {
		return "", fmt.Errorf("default keychain empty")
	}
	return keychain, nil
}

type execDarwinSecurityRunner struct{}

func (execDarwinSecurityRunner) CombinedOutput(args []string, stdin string) ([]byte, error) {
	cmd := exec.Command(securityPath, args...)
	if stdin == "" {
		return cmd.CombinedOutput()
	}
	pipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if _, err := io.WriteString(pipe, stdin); err != nil {
		_ = pipe.Close()
		_ = cmd.Wait()
		return nil, err
	}
	if err := pipe.Close(); err != nil {
		_ = cmd.Wait()
		return nil, err
	}
	return nil, cmd.Wait()
}

func decodeDarwinPassword(out string) (string, error) {
	value := strings.TrimSpace(out)
	if strings.HasPrefix(value, encodingPrefix) {
		decoded, err := hex.DecodeString(value[len(encodingPrefix):])
		return string(decoded), err
	}
	if strings.HasPrefix(value, base64EncodingPrefix) {
		decoded, err := base64.StdEncoding.DecodeString(value[len(base64EncodingPrefix):])
		return string(decoded), err
	}
	return value, nil
}

func quoteDarwinSecurityWord(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
