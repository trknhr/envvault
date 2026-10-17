package transfer

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"unicode/utf8"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/keyring"
	"golang.org/x/crypto/argon2"
)

const (
	formatVersion  = 1
	payloadVersion = 1
	aeadName       = "aes-256-gcm"
	kdfName        = "argon2id"
	saltLen        = 16
	nonceLen       = 12
	keyLen         = 32
	minPassphrase  = 8
	// MaxPassphraseLen is the longest passphrase Encrypt and Decrypt accept.
	MaxPassphraseLen = 1024
	maxFileBytes     = 8 << 20
)

// KDFParams are the Argon2id settings stored with an export file. Import uses
// the parameters from the file, after rejecting values outside a safe range.
type KDFParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// DefaultKDFParams is the passphrase stretching used by the CLI.
func DefaultKDFParams() KDFParams {
	return KDFParams{Time: 3, Memory: 64 * 1024, Threads: 4}
}

// TestKDFParams is a faster Argon2id setting for tests. It is still inside the
// range that import accepts.
func TestKDFParams() KDFParams {
	return KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}
}

func (p KDFParams) orDefault() KDFParams {
	if p == (KDFParams{}) {
		return DefaultKDFParams()
	}
	return p
}

func (p KDFParams) allowed() bool {
	return p.Time >= 1 && p.Time <= 4 && p.Memory >= 8*1024 && p.Memory <= 256*1024 && p.Threads >= 1 && p.Threads <= 8
}

type envelope struct {
	Version    int         `json:"envvault_export"`
	KDF        kdfEnvelope `json:"kdf"`
	AEAD       string      `json:"aead"`
	Nonce      string      `json:"nonce"`
	Verifier   string      `json:"verifier"`
	Ciphertext string      `json:"ciphertext"`
}

type kdfEnvelope struct {
	Name    string `json:"name"`
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	Salt    string `json:"salt"`
}

type header struct {
	Version int         `json:"envvault_export"`
	KDF     kdfEnvelope `json:"kdf"`
	AEAD    string      `json:"aead"`
	Nonce   string      `json:"nonce"`
}

// Encrypt seals plaintext with a passphrase. The passphrase buffer is not cleared.
func Encrypt(passphrase, plaintext []byte, params KDFParams) ([]byte, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	params = params.orDefault()
	if !params.allowed() {
		return nil, clerr.New(clerr.ConfigInvalid, "export KDF parameters are invalid")
	}
	salt := make([]byte, saltLen)
	defer keyring.Zero(salt)
	if _, err := rand.Read(salt); err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "generate export salt", err)
	}
	nonce := make([]byte, nonceLen)
	defer keyring.Zero(nonce)
	if _, err := rand.Read(nonce); err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "generate export nonce", err)
	}
	key := deriveKey(passphrase, salt, params)
	defer keyring.Zero(key)

	hdr := header{
		Version: formatVersion,
		KDF: kdfEnvelope{
			Name:    kdfName,
			Time:    params.Time,
			Memory:  params.Memory,
			Threads: params.Threads,
			Salt:    base64.StdEncoding.EncodeToString(salt),
		},
		AEAD:  aeadName,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
	}
	headerJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "encode export header", err)
	}
	verifier := keyVerifier(key, headerJSON)
	defer keyring.Zero(verifier)
	sealed, err := seal(key, nonce, plaintext, additionalData(headerJSON, verifier))
	if err != nil {
		return nil, err
	}
	defer keyring.Zero(sealed)
	body, err := json.Marshal(envelope{
		Version:    hdr.Version,
		KDF:        hdr.KDF,
		AEAD:       hdr.AEAD,
		Nonce:      hdr.Nonce,
		Verifier:   base64.StdEncoding.EncodeToString(verifier),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
	})
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "encode export file", err)
	}
	body = append(body, '\n')
	return body, nil
}

// Decrypt opens an export file. Wrong passphrases and tampering return distinct errors.
func Decrypt(passphrase, file []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, wrongPassphrase()
	}
	if len(passphrase) > MaxPassphraseLen {
		return nil, clerr.New(clerr.ConfigInvalid, "passphrase is too long")
	}
	if len(file) == 0 || len(file) > maxFileBytes {
		return nil, invalidFile()
	}
	var env envelope
	if err := json.Unmarshal(file, &env); err != nil {
		return nil, invalidFile()
	}
	if env.Version != formatVersion {
		return nil, clerr.New(clerr.ConfigInvalid, "unsupported export version")
	}
	if env.AEAD != aeadName || env.KDF.Name != kdfName {
		return nil, invalidFile()
	}
	params := KDFParams{Time: env.KDF.Time, Memory: env.KDF.Memory, Threads: env.KDF.Threads}
	if !params.allowed() {
		return nil, invalidFile()
	}
	salt, err := base64.StdEncoding.DecodeString(env.KDF.Salt)
	if err != nil || len(salt) != saltLen {
		return nil, invalidFile()
	}
	defer keyring.Zero(salt)
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return nil, invalidFile()
	}
	verifier, err := base64.StdEncoding.DecodeString(env.Verifier)
	if err != nil || len(verifier) != sha256.Size {
		return nil, invalidFile()
	}
	defer keyring.Zero(verifier)
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ciphertext) < 16 {
		return nil, invalidFile()
	}
	defer keyring.Zero(ciphertext)

	headerJSON, err := json.Marshal(header{
		Version: env.Version,
		KDF:     env.KDF,
		AEAD:    env.AEAD,
		Nonce:   env.Nonce,
	})
	if err != nil {
		return nil, invalidFile()
	}
	key := deriveKey(passphrase, salt, params)
	defer keyring.Zero(key)
	got := keyVerifier(key, headerJSON)
	defer keyring.Zero(got)
	if subtle.ConstantTimeCompare(verifier, got) != 1 {
		return nil, wrongPassphrase()
	}
	plaintext, err := open(key, nonce, ciphertext, additionalData(headerJSON, verifier))
	if err != nil {
		return nil, tampered()
	}
	return plaintext, nil
}

func validatePassphrase(passphrase []byte) error {
	if len(passphrase) > MaxPassphraseLen {
		return clerr.New(clerr.ConfigInvalid, "passphrase is too long")
	}
	if utf8.RuneCount(passphrase) < minPassphrase {
		return clerr.New(clerr.ConfigInvalid, "passphrase must be at least 8 characters")
	}
	if bytesContainsNUL(passphrase) {
		return clerr.New(clerr.ConfigInvalid, "passphrase contains invalid characters")
	}
	return nil
}

func bytesContainsNUL(value []byte) bool {
	for _, b := range value {
		if b == 0 {
			return true
		}
	}
	return false
}

func deriveKey(passphrase, salt []byte, params KDFParams) []byte {
	return argon2.IDKey(passphrase, salt, params.Time, params.Memory, params.Threads, keyLen)
}

func keyVerifier(key, headerJSON []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(headerJSON)
	return mac.Sum(nil)
}

func additionalData(headerJSON, verifier []byte) []byte {
	aad := make([]byte, 0, len(headerJSON)+len(verifier))
	aad = append(aad, headerJSON...)
	aad = append(aad, verifier...)
	return aad
}

func seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, invalidFile()
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, invalidFile()
	}
	return aead, nil
}

func wrongPassphrase() error {
	return clerr.New(clerr.ConfigInvalid, "wrong passphrase or export header was modified")
}

func tampered() error {
	return clerr.New(clerr.ConfigInvalid, "export file was tampered with")
}

func invalidFile() error {
	return clerr.New(clerr.ConfigInvalid, "export file is invalid")
}
