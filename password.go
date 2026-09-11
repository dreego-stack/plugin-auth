package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

type PasswordHasher interface {
	Hash(string) (string, error)
	Verify(string, string) (bool, error)
	NeedsRehash(string) bool
}

type Argon2idParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type Argon2idHasher struct {
	params Argon2idParams
}

func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}
}

func NewArgon2idHasher(params Argon2idParams) (*Argon2idHasher, error) {
	if params.Memory < 8*1024 || params.Memory > 1024*1024 || params.Iterations == 0 || params.Iterations > 20 || params.Parallelism == 0 || params.Parallelism > 32 || params.SaltLength < 16 || params.SaltLength > 64 || params.KeyLength < 16 || params.KeyLength > 64 {
		return nil, fmt.Errorf("auth: invalid Argon2id parameters")
	}
	return &Argon2idHasher{params: params}, nil
}

func (h *Argon2idHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, h.params.Memory, h.params.Iterations, h.params.Parallelism, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func (h *Argon2idHasher) Verify(encoded, password string) (bool, error) {
	params, salt, expected, err := parseArgon2id(encoded)
	if err != nil {
		return false, err
	}
	actual := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func (h *Argon2idHasher) NeedsRehash(encoded string) bool {
	params, _, _, err := parseArgon2id(encoded)
	return err != nil || params != h.params
}

func parseArgon2id(encoded string) (Argon2idParams, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return Argon2idParams{}, nil, nil, fmt.Errorf("auth: invalid Argon2id hash")
	}
	var memory, iterations uint64
	var parallelism uint64
	for value := range strings.SplitSeq(parts[3], ",") {
		key, raw, ok := strings.Cut(value, "=")
		if !ok {
			return Argon2idParams{}, nil, nil, fmt.Errorf("auth: invalid Argon2id hash")
		}
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return Argon2idParams{}, nil, nil, fmt.Errorf("auth: invalid Argon2id hash")
		}
		switch key {
		case "m":
			memory = parsed
		case "t":
			iterations = parsed
		case "p":
			parallelism = parsed
		default:
			return Argon2idParams{}, nil, nil, fmt.Errorf("auth: invalid Argon2id hash")
		}
	}
	params := Argon2idParams{Memory: uint32(memory), Iterations: uint32(iterations), Parallelism: uint8(parallelism)}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("auth: invalid Argon2id salt")
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil {
		return Argon2idParams{}, nil, nil, fmt.Errorf("auth: invalid Argon2id key")
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(key))
	if _, err := NewArgon2idHasher(params); err != nil {
		return Argon2idParams{}, nil, nil, err
	}
	return params, salt, key, nil
}
