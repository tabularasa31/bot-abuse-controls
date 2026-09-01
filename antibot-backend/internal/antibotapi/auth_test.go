package antibotapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/tabularasa31/bot-abuse-controls/antibot-backend/internal/antibotapi"
)

func TestNewAuthenticator_EmptyTokenReturnsNil(t *testing.T) {
	reg := prometheus.NewRegistry()
	if a := antibotapi.NewAuthenticator("", reg); a != nil {
		t.Errorf("NewAuthenticator(\"\") = %v, want nil", a)
	}
}

func TestAuthenticator_Middleware(t *testing.T) {
	reg := prometheus.NewRegistry()
	a := antibotapi.NewAuthenticator("s3cret", reg)
	if a == nil {
		t.Fatal("NewAuthenticator returned nil")
	}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := a.Middleware(next)

	cases := []struct {
		name       string
		header     string
		wantStatus int
		wantCalled bool
	}{
		{"missing", "", 401, false},
		{"empty bearer", "Bearer ", 401, false},
		{"wrong scheme", "Basic s3cret", 401, false},
		{"bad token", "Bearer wrong", 401, false},
		{"valid lowercase scheme", "bearer s3cret", 200, true},
		{"valid", "Bearer s3cret", 200, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Errorf("status: got %d, want %d", rr.Code, tc.wantStatus)
			}
			if called != tc.wantCalled {
				t.Errorf("next called: got %v, want %v", called, tc.wantCalled)
			}
			if tc.wantStatus == 401 && rr.Header().Get("WWW-Authenticate") == "" {
				t.Error("401 without WWW-Authenticate header")
			}
		})
	}
}
