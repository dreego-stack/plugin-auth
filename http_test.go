package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeRequestRejectsTrailingJSONAndUnknownContent(t *testing.T) {
	for _, test := range []struct {
		contentType string
		body        string
	}{
		{"application/json", `{"identifier":"user"} trailing`},
		{"text/plain", "identifier=user"},
	} {
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
		request.Header.Set("Content-Type", test.contentType)
		if err := decodeRequest(httptest.NewRecorder(), request, &credentialsInput{}); err == nil {
			t.Fatalf("decodeRequest accepted %s body %q", test.contentType, test.body)
		}
	}
}

func TestDecodeRequestSupportsCodeForms(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("id=one&code=12345678&purpose=login_code&password=secret"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var input verifyCodeInput
	if err := decodeRequest(httptest.NewRecorder(), request, &input); err != nil {
		t.Fatal(err)
	}
	if input.ID != "one" || input.Code != "12345678" || input.Purpose != PurposeLoginCode || input.Password != "secret" {
		t.Fatalf("decoded form = %+v", input)
	}
}
