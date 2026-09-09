package auth

import "errors"

var ErrNotFound = errors.New("auth: not found")
var ErrConflict = errors.New("auth: conflict")
var ErrExpired = errors.New("auth: expired")
var ErrAttemptsExceeded = errors.New("auth: attempts exceeded")
var ErrInvalidCredential = errors.New("auth: invalid credential")
var ErrDisabled = errors.New("auth: user disabled")
