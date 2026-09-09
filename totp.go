package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func generateTOTP(secret string, now time.Time, options TOTPOptions) (string, error) {
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil || len(decoded) < 16 {
		return "", ErrInvalidCredential
	}
	period := int64(options.Period / time.Second)
	if period <= 0 {
		return "", ErrInvalidCredential
	}
	counter := uint64(now.Unix() / period)
	message := make([]byte, 8)
	binary.BigEndian.PutUint64(message, counter)
	mac := hmac.New(sha1.New, decoded)
	mac.Write(message)
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	modulus := uint32(1)
	for i := 0; i < options.Digits; i++ {
		modulus *= 10
	}
	return fmt.Sprintf("%0*d", options.Digits, value%modulus), nil
}

func verifyTOTP(secret, candidate string, now time.Time, options TOTPOptions) bool {
	if len(candidate) != options.Digits {
		return false
	}
	if _, err := strconv.ParseUint(candidate, 10, 32); err != nil {
		return false
	}
	for window := -1; window <= 1; window++ {
		expected, err := generateTOTP(secret, now.Add(time.Duration(window)*options.Period), options)
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(candidate)) == 1 {
			return true
		}
	}
	return false
}
