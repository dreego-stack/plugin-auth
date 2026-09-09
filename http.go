package auth

import (
	"encoding/json"
	"errors"
	"io"
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
		if err := decoder.Decode(new(any)); err == nil {
			return errors.New("multiple JSON values")
		} else if !errors.Is(err, io.EOF) {
			return err
		}
		return nil
	}
	if mediaType != "application/x-www-form-urlencoded" && mediaType != "multipart/form-data" && mediaType != "" {
		return errors.New("unsupported content type")
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	switch data := target.(type) {
	case *credentialsInput:
		data.Identifier = r.FormValue("identifier")
		data.DisplayName = r.FormValue("displayName")
		data.Password = r.FormValue("password")
		data.Next = r.FormValue("next")
	case *codeInput:
		data.Code = r.FormValue("code")
	case *requestCodeInput:
		data.Identifier = r.FormValue("identifier")
		data.Purpose = Purpose(r.FormValue("purpose"))
	case *verifyCodeInput:
		data.ID = r.FormValue("id")
		data.Code = r.FormValue("code")
		data.Purpose = Purpose(r.FormValue("purpose"))
		data.Password = r.FormValue("password")
	default:
		return errors.New("form input is unsupported")
	}
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
