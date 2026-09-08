package auth

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
)

const maxRequestBody = 64 << 10

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeRequest(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaType == "application/json" {
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(target); err != nil {
			return err
		}
		if decoder.Decode(new(any)) == nil {
			return errors.New("multiple JSON values")
		}
		return nil
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	data, ok := target.(*credentialsInput)
	if !ok {
		return errors.New("form input is unsupported")
	}
	data.Identifier = r.FormValue("identifier")
	data.DisplayName = r.FormValue("displayName")
	data.Password = r.FormValue("password")
	data.Next = r.FormValue("next")
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	var response apiError
	response.Error.Code = code
	response.Error.Message = message
	writeJSON(w, status, response)
}

func safeNext(value string) string {
	if value == "" {
		return "/"
	}
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\\\r\n") {
		return "/"
	}
	return value
}
