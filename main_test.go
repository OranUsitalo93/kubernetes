package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockAuthenticator is a helper for testing.
type MockAuthenticator struct {
	AuthenticateFunc func(req *http.Request) (*AuthenticateResponse, bool, error)
}

func (m *MockAuthenticator) AuthenticateRequest(req *http.Request) (*AuthenticateResponse, bool, error) {
	return m.AuthenticateFunc(req)
}

func TestAuthenticationMiddleware_FailureStatusNotOverwritten(t *testing.T) {
	// Authenticator A fails and writes 403 Forbidden.
	authA := &MockAuthenticator{
		AuthenticateFunc: func(req *http.Request) (*AuthenticateResponse, bool, error) {
			if w := GetResponseWriter(req); w != nil {
				w.Header().Set("X-Reason", "AuthA-Failed")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("Forbidden by AuthA"))
			}
			return nil, false, errors.New("auth A failed")
		},
	}

	// Authenticator B attempts to write 401 Unauthorized.
	authB := &MockAuthenticator{
		AuthenticateFunc: func(req *http.Request) (*AuthenticateResponse, bool, error) {
			if w := GetResponseWriter(req); w != nil {
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized by AuthB"))
			}
			return nil, false, errors.New("auth B failed")
		},
	}

	union := NewUnionAuthenticator(authA, authB)

	failedHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Generic Unauthorized"))
	})

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := &AuthenticationMiddleware{
		Authenticator: union,
		FailedHandler: failedHandler,
		Next:          nextHandler,
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}

	if rec.Header().Get("X-Reason") != "AuthA-Failed" {
		t.Errorf("expected header X-Reason to be 'AuthA-Failed', got '%s'", rec.Header().Get("X-Reason"))
	}

	if rec.Body.String() != "Forbidden by AuthA" {
		t.Errorf("expected body 'Forbidden by AuthA', got '%s'", rec.Body.String())
	}
}

func TestAuthenticationMiddleware_ShortCircuit(t *testing.T) {
	authACalled := false
	authBCalled := false

	authA := &MockAuthenticator{
		AuthenticateFunc: func(req *http.Request) (*AuthenticateResponse, bool, error) {
			authACalled = true
			if w := GetResponseWriter(req); w != nil {
				w.WriteHeader(http.StatusForbidden)
			}
			return nil, false, errors.New("auth A failed")
		},
	}

	authB := &MockAuthenticator{
		AuthenticateFunc: func(req *http.Request) (*AuthenticateResponse, bool, error) {
			authBCalled = true
			return nil, false, nil
		},
	}

	union := NewUnionAuthenticator(authA, authB)

	failedHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	middleware := &AuthenticationMiddleware{
		Authenticator: union,
		FailedHandler: failedHandler,
		Next: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	middleware.ServeHTTP(rec, req)

	if !authACalled {
		t.Error("expected Authenticator A to be called")
	}
	if authBCalled {
		t.Error("expected Authenticator B to be short-circuited and not called")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status %d, got %d", http.StatusForbidden, rec.Code)
	}
}

func TestAuthenticationMiddleware_CustomHeaders(t *testing.T) {
	auth := &MockAuthenticator{
		AuthenticateFunc: func(req *http.Request) (*AuthenticateResponse, bool, error) {
			headers := make(http.Header)
			headers.Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			return nil, false, &AuthenticationError{
				Message:    "invalid token",
				StatusCode: http.StatusUnauthorized,
				Headers:    headers,
			}
		},
	}

	middleware := &AuthenticationMiddleware{
		Authenticator: auth,
		FailedHandler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}),
		Next: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}

	if rec.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Errorf("expected WWW-Authenticate header, got '%s'", rec.Header().Get("WWW-Authenticate"))
	}
}

func TestAuthenticationMiddleware_AnonymousFallback(t *testing.T) {
	auth := &MockAuthenticator{
		AuthenticateFunc: func(req *http.Request) (*AuthenticateResponse, bool, error) {
			return nil, false, nil
		},
	}

	anonymousUser := &DefaultUserInfo{Name: "system:anonymous"}

	middleware := &AuthenticationMiddleware{
		Authenticator:    auth,
		FailedHandler:    http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(http.StatusUnauthorized) }),
		AnonymousEnabled: true,
		AnonymousUser:    anonymousUser,
		Next: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			user, ok := req.Context().Value("user").(UserInfo)
			if !ok || user.GetName() != "system:anonymous" {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}),
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
}
