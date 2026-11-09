package authstate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/trknhr/envvault/internal/keyring"
)

type Store struct {
	Dir  string
	Keys keyring.Store
}
type Record struct {
	Metadata Metadata
	Document []byte
}

func (r *Record) Zero()           { keyring.Zero(r.Document); r.Document = nil }
func (r Record) String() string   { return "authentication record [REDACTED]" }
func (r Record) GoString() string { return r.String() }

type envelope struct {
	Version    int      `json:"version"`
	Metadata   Metadata `json:"metadata"`
	Nonce      []byte   `json:"nonce"`
	Ciphertext []byte   `json:"ciphertext"`
}

func validID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == id
}

// EncryptionKey identifies the small wrapping key stored in the OS keyring.
func EncryptionKey(id string) keyring.Key { return keyring.Key("envvault/auth-profile/" + id + "/key") }
func storageKey(id string) keyring.Key    { return EncryptionKey(id) }

func (s Store) root() (*os.Root, error) {
	if s.Dir == "" || !filepath.IsAbs(s.Dir) || s.Keys == nil {
		return nil, errors.New("authentication storage is unavailable")
	}
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return nil, errors.New("authentication storage is unavailable")
	}
	info, err := os.Lstat(s.Dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("authentication directory is unsafe")
	}
	if os.Chmod(s.Dir, 0700) != nil {
		return nil, errors.New("authentication directory permissions unavailable")
	}
	root, err := os.OpenRoot(s.Dir)
	if err != nil {
		return nil, errors.New("authentication storage is unavailable")
	}
	return root, nil
}

func (s Store) ReadMetadata(id string) (Metadata, error) {
	root, err := s.root()
	if err != nil {
		return Metadata{}, err
	}
	defer root.Close()
	env, err := readEnvelope(root, id)
	return env.Metadata, err
}

func readEnvelope(root *os.Root, id string) (envelope, error) {
	if !validID(id) {
		return envelope{}, errors.New("invalid authentication record ID")
	}
	info, err := root.Lstat(id + ".json")
	if err != nil || !info.Mode().IsRegular() || info.Size() > 2*MaxDocumentBytes {
		return envelope{}, errors.New("authentication record unavailable")
	}
	f, err := root.Open(id + ".json")
	if err != nil {
		return envelope{}, errors.New("authentication record unavailable")
	}
	defer f.Close()
	var env envelope
	d := json.NewDecoder(io.LimitReader(f, 2*MaxDocumentBytes))
	d.DisallowUnknownFields()
	if d.Decode(&env) != nil || d.Decode(new(any)) != io.EOF || env.Version != 1 || env.Metadata.ID != id || env.Metadata.Validate() != nil {
		return envelope{}, errors.New("invalid authentication record")
	}
	return env, nil
}

func aad(metadata Metadata) []byte {
	data, _ := json.Marshal(struct {
		Version  int
		Metadata Metadata
	}{1, metadata})
	return data
}

func (s Store) Read(ctx context.Context, id string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	root, err := s.root()
	if err != nil {
		return Record{}, err
	}
	defer root.Close()
	env, err := readEnvelope(root, id)
	if err != nil {
		return Record{}, err
	}
	key, err := s.Keys.Get(ctx, storageKey(id))
	if err != nil {
		return Record{}, errors.New("authentication encryption key unavailable")
	}
	defer keyring.Zero(key)
	if len(key) != 32 {
		return Record{}, errors.New("invalid authentication encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Record{}, errors.New("authentication decryption failed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(env.Nonce) != aead.NonceSize() {
		return Record{}, errors.New("authentication decryption failed")
	}
	plain, err := aead.Open(nil, env.Nonce, env.Ciphertext, aad(env.Metadata))
	if err != nil {
		return Record{}, errors.New("authentication record is corrupt or modified")
	}
	if len(plain) > MaxDocumentBytes {
		keyring.Zero(plain)
		return Record{}, errors.New("authentication document exceeds size limit")
	}
	return Record{Metadata: env.Metadata, Document: plain}, nil
}

// Put creates a new key for a new profile, or atomically replaces an existing
// record using a fresh nonce. The caller owns namespace registration.
func (s Store) Put(ctx context.Context, metadata Metadata, document []byte) (Metadata, error) {
	if err := metadata.Validate(); err != nil {
		return Metadata{}, err
	}
	canonical, err := Parse(document, "json")
	if err != nil {
		return Metadata{}, err
	}
	defer keyring.Zero(canonical)
	value, err := Token(canonical, metadata.TokenField)
	if err != nil {
		return Metadata{}, err
	}
	keyring.Zero(value)
	if _, err := Expiry(canonical, metadata.ExpiresField); err != nil {
		return Metadata{}, err
	}
	created := metadata.ID == ""
	if created {
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			return Metadata{}, errors.New("authentication ID generation failed")
		}
		metadata.ID = hex.EncodeToString(id)
	}
	err = s.WithLock(ctx, metadata.ID, func() error {
		if created {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return errors.New("authentication key generation failed")
			}
			defer keyring.Zero(key)
			if err := s.Keys.Put(ctx, storageKey(metadata.ID), key); err != nil {
				return errors.New("authentication encryption key could not be stored")
			}
		} else {
			previous, err := s.ReadMetadata(metadata.ID)
			if err != nil || previous.Name != metadata.Name {
				return errors.New("authentication record identity mismatch")
			}
		}
		if err := s.write(ctx, metadata, canonical); err != nil {
			if created {
				_ = s.Keys.Delete(context.WithoutCancel(ctx), storageKey(metadata.ID))
			}
			return err
		}
		return nil
	})
	return metadata, err
}

func (s Store) write(ctx context.Context, metadata Metadata, document []byte) error {
	root, err := s.root()
	if err != nil {
		return err
	}
	defer root.Close()
	key, err := s.Keys.Get(ctx, storageKey(metadata.ID))
	if err != nil {
		return errors.New("authentication encryption key unavailable")
	}
	defer keyring.Zero(key)
	if len(key) != 32 {
		return errors.New("invalid authentication encryption key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return errors.New("authentication encryption failed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return errors.New("authentication encryption failed")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return errors.New("authentication nonce generation failed")
	}
	data, err := json.Marshal(envelope{Version: 1, Metadata: metadata, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, document, aad(metadata))})
	if err != nil {
		return errors.New("authentication record encoding failed")
	}
	tmp := metadata.ID + "." + rand.Text() + ".tmp"
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("authentication record write failed")
	}
	defer root.Remove(tmp)
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("authentication record write failed")
	}
	if root.Rename(tmp, metadata.ID+".json") != nil {
		return errors.New("authentication record replacement failed")
	}
	return nil
}

// Update serializes refresh across processes. The callback must not retain the
// record, and may change the document without changing its identity.
func (s Store) Update(ctx context.Context, id string, change func(*Record) (bool, error)) error {
	return s.WithLock(ctx, id, func() error {
		record, err := s.Read(ctx, id)
		if err != nil {
			return err
		}
		defer record.Zero()
		original := record.Metadata
		changed, err := change(&record)
		if err != nil {
			return err
		}
		if !changed {
			return nil
		}
		if record.Metadata.ID != original.ID || record.Metadata.Name != original.Name || record.Metadata.Validate() != nil {
			return errors.New("authentication update changed profile identity")
		}
		canonical, err := Parse(record.Document, "json")
		defer keyring.Zero(canonical)
		if err != nil {
			return err
		}
		value, err := Token(canonical, record.Metadata.TokenField)
		keyring.Zero(value)
		if err != nil {
			return err
		}
		if _, err := Expiry(canonical, record.Metadata.ExpiresField); err != nil {
			return err
		}
		return s.write(ctx, record.Metadata, canonical)
	})
}

func (s Store) Delete(ctx context.Context, id string) error {
	return s.WithLock(ctx, id, func() error {
		if !validID(id) {
			return errors.New("invalid authentication record ID")
		}
		root, err := s.root()
		if err != nil {
			return err
		}
		defer root.Close()
		// Remove the decryption key first, so a failed file removal fails closed.
		key, err := s.Keys.Get(ctx, storageKey(id))
		keyring.Zero(key)
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return errors.New("authentication key unavailable for removal")
		}
		if err == nil {
			if err := s.Keys.Delete(ctx, storageKey(id)); err != nil {
				return errors.New("authentication key removal failed")
			}
		}
		if err := root.Remove(id + ".json"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("authentication record removal failed")
		}
		return nil
	})
}

func (s Store) WithLock(ctx context.Context, name string, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if name == "" || bytes.ContainsAny([]byte(name), "/\\\x00") {
		return errors.New("invalid authentication lock")
	}
	root, err := s.root()
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.OpenFile(".lock-"+name, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return errors.New("authentication lock unavailable")
	}
	defer f.Close()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		locked, err := tryLock(f)
		if err != nil {
			return errors.New("authentication lock unavailable")
		}
		if locked {
			defer unlock(f)
			return fn()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
