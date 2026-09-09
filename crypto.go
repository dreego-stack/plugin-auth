package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

func deriveKey(secret []byte, label string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("dreego-plugin-auth:" + label))
	return mac.Sum(nil)
}

func encryptValue(secret []byte, label string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(deriveKey(secret, label))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte(label)), nil
}

func decryptValue(secret []byte, label string, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(deriveKey(secret, label))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, ErrInvalidCredential
	}
	nonce := ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], []byte(label))
}

func codeProof(secret []byte, label, code string) []byte {
	cleaned := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(code))
	mac := hmac.New(sha256.New, deriveKey(secret, label))
	mac.Write([]byte(cleaned))
	return mac.Sum(nil)
}

func randomBase32(size int) (string, error) {
	value, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(value), nil
}
